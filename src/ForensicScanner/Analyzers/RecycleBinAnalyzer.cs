using ForensicScanner.Models;
using ForensicScanner.Services;
using ForensicScanner.Utilities;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;

namespace ForensicScanner.Analyzers;

public sealed class RecycleBinAnalyzer : IArtifactAnalyzer
{
    public ArtifactCategory Category => ArtifactCategory.RecycleBin;

    public Task<IReadOnlyCollection<ForensicFinding>> AnalyzeAsync(ScanContext context, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            context.Logger.Warn("Recycle Bin analysis is only available on Windows hosts.");
            return Task.FromResult<IReadOnlyCollection<ForensicFinding>>(Array.Empty<ForensicFinding>());
        }

        var findings = new List<ForensicFinding>();
        var drives = DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed).ToList();
        foreach (var drive in drives)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!drive.IsReady)
            {
                continue;
            }

            string recycleRoot = Path.Combine(drive.RootDirectory.FullName, "$Recycle.Bin");
            if (!Directory.Exists(recycleRoot))
            {
                continue;
            }

            if (!string.Equals(drive.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new ForensicFinding(
                    Severity.Low,
                    Category,
                    "Recycle Bin metadata limited on non-NTFS drive",
                    recycleRoot,
                    context.Options.ScanTimestampUtc,
                    $"Drive format: {drive.DriveFormat}"));
            }

            var rootInfo = new DirectoryInfo(recycleRoot);
            if (DateTime.UtcNow - rootInfo.LastWriteTimeUtc < TimeSpan.FromHours(6))
            {
                findings.Add(new ForensicFinding(
                    Severity.Medium,
                    Category,
                    "Recycle Bin recently modified",
                    recycleRoot,
                    rootInfo.LastWriteTimeUtc,
                    $"Last write time: {rootInfo.LastWriteTime}");
            }

            AnalyzeRecycleRoot(context, recycleRoot, findings, cancellationToken);
        }

        return Task.FromResult<IReadOnlyCollection<ForensicFinding>>(new ReadOnlyCollection<ForensicFinding>(findings));
    }

    private static void AnalyzeRecycleRoot(ScanContext context, string recycleRoot, ICollection<ForensicFinding> findings, CancellationToken token)
    {
        IEnumerable<string> sidDirectories;
        try
        {
            sidDirectories = Directory.EnumerateDirectories(recycleRoot).ToList();
        }
        catch (Exception ex)
        {
            context.Logger.Warn($"Unable to enumerate {recycleRoot}: {ex.Message}");
            return;
        }

        foreach (var sidDirectory in sidDirectories)
        {
            token.ThrowIfCancellationRequested();
            var directoryName = Path.GetFileName(sidDirectory);
            if (context.Options.TargetUserSids.Count > 0 && !context.Options.TargetUserSids.Contains(directoryName, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            try
            {
                var data = new DirectoryInfo(sidDirectory);
                foreach (var metadataFile in data.EnumerateFiles("$I*", SearchOption.TopDirectoryOnly))
                {
                    token.ThrowIfCancellationRequested();
                    var entry = ParseMetadata(metadataFile.FullName, context);
                    if (entry is null)
                    {
                        continue;
                    }

                    var severity = DetermineSeverity(entry, context);
                    var description = DescribeEntry(entry, severity);
                    var contextText = BuildContextText(entry);

                    findings.Add(new ForensicFinding(
                        severity,
                        ArtifactCategory.RecycleBin,
                        description,
                        metadataFile.FullName,
                        entry.DeletionTime,
                        contextText));

                    var recycleDataPath = Path.Combine(metadataFile.DirectoryName!, metadataFile.Name.Replace("$I", "$R", StringComparison.OrdinalIgnoreCase));
                    if (!File.Exists(recycleDataPath))
                    {
                        findings.Add(new ForensicFinding(
                            Severity.Medium,
                            ArtifactCategory.RecycleBin,
                            "Metadata file missing $R counterpart (possible shift-delete or wiping)",
                            metadataFile.FullName,
                            entry.DeletionTime,
                            entry.OriginalPath));
                    }
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                context.Logger.Warn($"Access denied for {sidDirectory}: {ex.Message}");
            }
            catch (IOException ex)
            {
                context.Logger.Verbose($"Failed to enumerate files in {sidDirectory}: {ex.Message}");
            }
        }
    }

    private static string BuildContextText(RecycleEntry entry)
    {
        var builder = new StringBuilder();
        builder.Append("Original Path: ").Append(entry.OriginalPath);
        builder.Append(" | Size: ").Append(entry.OriginalSizeBytes).Append(" bytes");
        if (!string.IsNullOrWhiteSpace(entry.RecycleDataPath))
        {
            builder.Append(" | Data File: ").Append(entry.RecycleDataPath);
        }
        return builder.ToString();
    }

    private static Severity DetermineSeverity(RecycleEntry entry, ScanContext context)
    {
        bool cheatIndicator = KeywordCatalog.ContainsCheatIndicator(entry.OriginalPath);
        bool suspiciousLocation = KeywordCatalog.ContainsSuspiciousDirectory(entry.OriginalPath);
        bool recentDeletion = context.Options.ScanTimestampUtc - entry.DeletionTime < TimeSpan.FromMinutes(45);

        if (cheatIndicator && recentDeletion)
        {
            return Severity.Critical;
        }

        if (cheatIndicator)
        {
            return Severity.High;
        }

        if (recentDeletion || suspiciousLocation)
        {
            return Severity.Medium;
        }

        return Severity.Low;
    }

    private static string DescribeEntry(RecycleEntry entry, Severity severity) => severity switch
    {
        Severity.Critical => "Cheat-related file deleted moments before scan",
        Severity.High => "Cheat-related file present in Recycle Bin",
        Severity.Medium => "Recently deleted file from suspicious directory",
        _ => "Historical Recycle Bin entry"
    };

    private static RecycleEntry? ParseMetadata(string metadataPath, ScanContext context)
    {
        try
        {
            using var stream = File.Open(metadataPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new BinaryReader(stream, Encoding.Unicode, leaveOpen: false);
            var version = reader.ReadByte();
            reader.BaseStream.Seek(7, SeekOrigin.Current); // skip padding
            long originalSize = reader.ReadInt64();
            long deletionFileTime = reader.ReadInt64();
            var originalPath = ReadNullTerminatedString(reader);
            var deletionTime = DateTimeOffset.FromFileTime(deletionFileTime).ToLocalTime();
            var recycleDataPath = Path.Combine(Path.GetDirectoryName(metadataPath) ?? string.Empty, Path.GetFileName(metadataPath).Replace("$I", "$R", StringComparison.OrdinalIgnoreCase));

            return new RecycleEntry
            {
                OriginalPath = originalPath,
                OriginalSizeBytes = originalSize,
                DeletionTime = deletionTime,
                RecycleDataPath = recycleDataPath,
                MetadataPath = metadataPath,
                Version = version
            };
        }
        catch (Exception ex)
        {
            context.Logger.Verbose($"Failed to parse {metadataPath}: {ex.Message}");
            return null;
        }
    }

    private static string ReadNullTerminatedString(BinaryReader reader)
    {
        var chars = new List<char>();
        while (reader.BaseStream.Position < reader.BaseStream.Length)
        {
            var c = reader.ReadChar();
            if (c == '\0')
            {
                break;
            }
            chars.Add(c);
        }
        return new string(chars.ToArray());
    }

    private sealed class RecycleEntry
    {
        public string OriginalPath { get; init; } = string.Empty;
        public long OriginalSizeBytes { get; init; }
        public DateTimeOffset DeletionTime { get; init; }
        public string RecycleDataPath { get; init; } = string.Empty;
        public string MetadataPath { get; init; } = string.Empty;
        public byte Version { get; init; }
    }
}
