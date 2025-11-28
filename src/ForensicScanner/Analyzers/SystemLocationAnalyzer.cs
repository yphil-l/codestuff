using ForensicScanner.Models;
using ForensicScanner.Services;
using ForensicScanner.Utilities;
using Microsoft.Win32;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml.Linq;

namespace ForensicScanner.Analyzers;

public sealed class SystemLocationAnalyzer : IArtifactAnalyzer
{
    private static readonly string[] HighRiskPowerShellCommands =
    {
        "Add-MpPreference",
        "Set-MpPreference",
        "wevtutil",
        "Clear-EventLog",
        "Remove-EventLog",
        "Remove-Item",
        "Set-ItemProperty",
        "schtasks",
        "-ExecutionPolicy Bypass",
        "rundll32",
        "reg add",
        "netsh advfirewall",
        "DisableRealtimeMonitoring"
    };

    private static readonly string[] MediumRiskPowerShellCommands =
    {
        "Invoke-WebRequest",
        "Invoke-Expression",
        "bitsadmin",
        "Start-BitsTransfer",
        "DownloadFile",
        "Set-Service",
        "Stop-Service",
        "New-Service",
        "Copy-Item"
    };

    public ArtifactCategory Category => ArtifactCategory.SystemLocations;

    public Task<IReadOnlyCollection<ForensicFinding>> AnalyzeAsync(ScanContext context, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            context.Logger.Warn("System location analysis is only available on Windows hosts.");
            return Task.FromResult<IReadOnlyCollection<ForensicFinding>>(Array.Empty<ForensicFinding>());
        }

        var findings = new List<ForensicFinding>();
        AnalyzeScheduledTasks(context, findings, cancellationToken);
        AnalyzeAppCompatArtifacts(context, findings);
        AnalyzePowerShellHistory(context, findings, cancellationToken);
        AnalyzeCustomPaths(context, findings, cancellationToken);

        return Task.FromResult<IReadOnlyCollection<ForensicFinding>>(new ReadOnlyCollection<ForensicFinding>(findings));
    }

    private static void AnalyzeScheduledTasks(ScanContext context, ICollection<ForensicFinding> findings, CancellationToken token)
    {
        var tasksRoot = PathUtilities.GetWindowsPath("System32", "Tasks");
        if (!Directory.Exists(tasksRoot))
        {
            return;
        }

        foreach (var taskFile in Directory.EnumerateFiles(tasksRoot, "*", SearchOption.AllDirectories).Take(1500))
        {
            token.ThrowIfCancellationRequested();

            try
            {
                var xml = File.ReadAllText(taskFile);
                var document = XDocument.Parse(xml);
                var ns = document.Root?.Name.Namespace ?? XNamespace.None;
                var command = document.Descendants(ns + "Command").FirstOrDefault()?.Value ?? string.Empty;
                var arguments = document.Descendants(ns + "Arguments").FirstOrDefault()?.Value ?? string.Empty;
                var triggers = document.Descendants(ns + "Triggers")
                    .Descendants()
                    .Select(t => t.Name.LocalName)
                    .Distinct()
                    .ToArray();
                var triggerSummary = triggers.Length == 0 ? "None" : string.Join(",", triggers);

                var severity = ClassifyTask(command, arguments, triggerSummary);
                if (severity is null)
                {
                    continue;
                }

                var description = severity switch
                {
                    Severity.Critical => "Scheduled task clears logs or tampers with security",
                    Severity.High => "Suspicious scheduled task persistence detected",
                    Severity.Medium => "Potential persistence task configured",
                    _ => "Scheduled task insight"
                };

                var contextText = $"Command: {command} {arguments} | Triggers: {triggerSummary}";
                var timestamp = new DateTimeOffset(File.GetLastWriteTimeUtc(taskFile));

                findings.Add(new ForensicFinding(
                    severity.Value,
                    ArtifactCategory.SystemLocations,
                    description,
                    taskFile,
                    timestamp,
                    contextText));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Xml.XmlException)
            {
                context.Logger.Verbose($"Unable to parse scheduled task {taskFile}: {ex.Message}");
            }
        }
    }

    private static Severity? ClassifyTask(string command, string arguments, string triggers)
    {
        var commandLine = $"{command} {arguments}".Trim();
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return null;
        }

        if (KeywordCatalog.LogClearingCommands.Any(cmd => commandLine.Contains(cmd, StringComparison.OrdinalIgnoreCase)))
        {
            return Severity.Critical;
        }

        if (KeywordCatalog.ContainsCheatIndicator(commandLine) || PathUtilities.IsUserWritablePath(commandLine))
        {
            return Severity.High;
        }

        if (commandLine.Contains("powershell", StringComparison.OrdinalIgnoreCase) && commandLine.Contains("ExecutionPolicy", StringComparison.OrdinalIgnoreCase))
        {
            return Severity.High;
        }

        if (triggers.Contains("Logon", StringComparison.OrdinalIgnoreCase) || triggers.Contains("Boot", StringComparison.OrdinalIgnoreCase))
        {
            return Severity.Medium;
        }

        return null;
    }

    private static void AnalyzeAppCompatArtifacts(ScanContext context, ICollection<ForensicFinding> findings)
    {
        AnalyzeCompatibilityAssistantStore(context, findings);
        var recentFileCache = PathUtilities.GetWindowsPath("AppCompat", "Programs", "RecentFileCache.bcf");
        AnalyzeBinaryArtifact(context, recentFileCache, "RecentFileCache.bcf", Severity.Medium, findings, limitBytes: 4 * 1024 * 1024);
        var amcache = PathUtilities.GetWindowsPath("AppCompat", "Programs", "Amcache.hve");
        AnalyzeBinaryArtifact(context, amcache, "Amcache.hve", Severity.High, findings, limitBytes: 6 * 1024 * 1024);
    }

    private static void AnalyzeCompatibilityAssistantStore(ScanContext context, ICollection<ForensicFinding> findings)
    {
        const string relativePath = "Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store";
        foreach (var sid in ResolveUserSids(context))
        {
            var hivePath = $"{sid}\\{relativePath}";
            using var key = OpenUserKey(context, hivePath);
            if (key is null)
            {
                continue;
            }

            foreach (var valueName in key.GetValueNames())
            {
                var data = key.GetValue(valueName);
                var valueText = data switch
                {
                    string s => s,
                    byte[] bytes => Encoding.Unicode.GetString(bytes).TrimEnd('\0'),
                    _ => valueName
                };

                if (KeywordCatalog.ContainsCheatIndicator(valueText))
                {
                    findings.Add(new ForensicFinding(
                        Severity.High,
                        ArtifactCategory.SystemLocations,
                        "Program Compatibility Assistant recorded cheat-related execution",
                        $"HKU:{hivePath}",
                        context.Options.ScanTimestampUtc,
                        valueText));
                    continue;
                }

                if (PathUtilities.IsUserWritablePath(valueText))
                {
                    findings.Add(new ForensicFinding(
                        Severity.Medium,
                        ArtifactCategory.SystemLocations,
                        "Program Compatibility Assistant logged execution from user-writable path",
                        $"HKU:{hivePath}",
                        context.Options.ScanTimestampUtc,
                        valueText));
                }
            }
        }
    }

    private static void AnalyzeBinaryArtifact(ScanContext context, string path, string artifactName, Severity severity, ICollection<ForensicFinding> findings, int limitBytes)
    {
        if (!File.Exists(path))
        {
            return;
        }

        try
        {
            using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var length = (int)Math.Min(limitBytes, stream.Length);
            var buffer = new byte[length];
            _ = stream.Read(buffer, 0, length);

            var strings = ExtractStrings(buffer, 6)
                .Where(KeywordCatalog.ContainsCheatIndicator)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(15)
                .ToList();

            foreach (var match in strings)
            {
                findings.Add(new ForensicFinding(
                    severity,
                    ArtifactCategory.SystemLocations,
                    $"{artifactName} contains suspicious execution reference",
                    path,
                    new DateTimeOffset(File.GetLastWriteTimeUtc(path)),
                    match));
            }
        }
        catch (Exception ex)
        {
            context.Logger.Verbose($"Failed to analyze {artifactName}: {ex.Message}");
        }
    }

    private static IEnumerable<string> ExtractStrings(byte[] buffer, int minLength)
    {
        var asciiBuilder = new StringBuilder();
        var unicodeBuilder = new StringBuilder();

        for (int i = 0; i < buffer.Length; i++)
        {
            var b = buffer[i];
            if (b >= 32 && b < 127)
            {
                asciiBuilder.Append((char)b);
            }
            else
            {
                if (asciiBuilder.Length >= minLength)
                {
                    yield return asciiBuilder.ToString();
                }
                asciiBuilder.Clear();
            }
        }

        if (asciiBuilder.Length >= minLength)
        {
            yield return asciiBuilder.ToString();
        }

        // Basic UTF-16LE parsing
        for (int i = 0; i < buffer.Length - 1; i += 2)
        {
            char c = (char)(buffer[i] | (buffer[i + 1] << 8));
            if (char.IsLetterOrDigit(c) || char.IsPunctuation(c) || char.IsWhiteSpace(c))
            {
                unicodeBuilder.Append(c);
            }
            else
            {
                if (unicodeBuilder.Length >= minLength)
                {
                    yield return unicodeBuilder.ToString();
                }
                unicodeBuilder.Clear();
            }
        }

        if (unicodeBuilder.Length >= minLength)
        {
            yield return unicodeBuilder.ToString();
        }
    }

    private static void AnalyzePowerShellHistory(ScanContext context, ICollection<ForensicFinding> findings, CancellationToken token)
    {
        var profiles = ResolveProfilePaths(context);
        foreach (var profile in profiles)
        {
            token.ThrowIfCancellationRequested();
            var historyPath = Path.Combine(profile, "AppData", "Roaming", "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");
            if (!File.Exists(historyPath))
            {
                continue;
            }

            IEnumerable<string> lines;
            try
            {
                lines = File.ReadLines(historyPath).TakeLast(250).ToList();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                context.Logger.Verbose($"Unable to read PowerShell history ({historyPath}): {ex.Message}");
                continue;
            }

            var timestamp = new DateTimeOffset(File.GetLastWriteTimeUtc(historyPath));
            foreach (var line in lines)
            {
                token.ThrowIfCancellationRequested();
                var trimmed = line.Trim();
                var severity = ClassifyPowerShellCommand(trimmed);
                if (severity is null)
                {
                    continue;
                }

                var description = severity == Severity.High
                    ? "Malicious PowerShell command recorded"
                    : "Suspicious PowerShell command recorded";

                findings.Add(new ForensicFinding(
                    severity.Value,
                    ArtifactCategory.SystemLocations,
                    description,
                    historyPath,
                    timestamp,
                    trimmed));
            }
        }
    }

    private static Severity? ClassifyPowerShellCommand(string command)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return null;
        }

        if (KeywordCatalog.ContainsCheatIndicator(command))
        {
            return Severity.High;
        }

        if (HighRiskPowerShellCommands.Any(cmd => command.Contains(cmd, StringComparison.OrdinalIgnoreCase)))
        {
            return Severity.High;
        }

        if (MediumRiskPowerShellCommands.Any(cmd => command.Contains(cmd, StringComparison.OrdinalIgnoreCase))
            || PathUtilities.IsUserWritablePath(command))
        {
            return Severity.Medium;
        }

        return null;
    }

    private static void AnalyzeCustomPaths(ScanContext context, ICollection<ForensicFinding> findings, CancellationToken token)
    {
        foreach (var customPath in context.Options.CustomPaths)
        {
            if (string.IsNullOrWhiteSpace(customPath))
            {
                continue;
            }

            token.ThrowIfCancellationRequested();

            try
            {
                if (File.Exists(customPath))
                {
                    EvaluateCustomFile(customPath, findings);
                }
                else if (Directory.Exists(customPath))
                {
                    int scanned = 0;
                    foreach (var file in Directory.EnumerateFiles(customPath, "*", SearchOption.AllDirectories))
                    {
                        token.ThrowIfCancellationRequested();
                        EvaluateCustomFile(file, findings);
                        scanned++;
                        if (scanned > 500)
                        {
                            break;
                        }
                    }
                }
                else
                {
                    context.Logger.Warn($"Custom path not found: {customPath}");
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                context.Logger.Warn($"Unable to scan custom path {customPath}: {ex.Message}");
            }
        }
    }

    private static void EvaluateCustomFile(string filePath, ICollection<ForensicFinding> findings)
    {
        var fileName = Path.GetFileName(filePath);
        var indicator = KeywordCatalog.ContainsCheatIndicator(fileName);
        if (!indicator)
        {
            return;
        }

        var fileInfo = new FileInfo(filePath);
        var timestamp = new DateTimeOffset(fileInfo.LastWriteTimeUtc);
        var contextText = $"Size: {fileInfo.Length} bytes";

        findings.Add(new ForensicFinding(
            Severity.High,
            ArtifactCategory.SystemLocations,
            "Custom path contains cheat-related binary",
            filePath,
            timestamp,
            contextText));
    }

    private static IEnumerable<string> ResolveUserSids(ScanContext context)
    {
        if (context.Options.TargetUserSids.Count > 0)
        {
            return context.Options.TargetUserSids;
        }

        try
        {
            using var hive = RegistryKey.OpenBaseKey(RegistryHive.Users, context.RegistryView);
            return hive.GetSubKeyNames()
                .Where(name => name.StartsWith("S-1-5", StringComparison.OrdinalIgnoreCase) && !name.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase))
                .ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static RegistryKey? OpenUserKey(ScanContext context, string path)
    {
        try
        {
            return RegistryKey.OpenBaseKey(RegistryHive.Users, context.RegistryView).OpenSubKey(path);
        }
        catch
        {
            return null;
        }
    }

    private static IReadOnlyCollection<string> ResolveProfilePaths(ScanContext context)
    {
        if (context.Cache.TryGetValue<IReadOnlyCollection<string>>("profilePaths", out var cached))
        {
            return cached;
        }

        var profileMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var profileRoot = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, context.RegistryView)
                .OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList");
            if (profileRoot is not null)
            {
                foreach (var sid in profileRoot.GetSubKeyNames())
                {
                    using var profileKey = profileRoot.OpenSubKey(sid);
                    var path = profileKey?.GetValue("ProfileImagePath")?.ToString();
                    if (!string.IsNullOrWhiteSpace(path))
                    {
                        profileMap[sid] = Environment.ExpandEnvironmentVariables(path);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            context.Logger.Verbose($"Failed to query profile list: {ex.Message}");
        }

        IEnumerable<string> candidates;
        if (context.Options.TargetUserSids.Count > 0)
        {
            candidates = context.Options.TargetUserSids
                .Select(sid => profileMap.TryGetValue(sid, out var path) ? path : null)
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .Select(path => path!)
                .Distinct(StringComparer.OrdinalIgnoreCase);
        }
        else
        {
            candidates = profileMap.Values.Distinct(StringComparer.OrdinalIgnoreCase);
        }

        var list = candidates
            .Where(path => !string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
            .ToList();

        if (list.Count == 0)
        {
            var fallbackRoot = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\", "Users");
            if (Directory.Exists(fallbackRoot))
            {
                list.AddRange(Directory.EnumerateDirectories(fallbackRoot)
                    .Where(dir => !dir.EndsWith("Public", StringComparison.OrdinalIgnoreCase) && !dir.EndsWith("Default", StringComparison.OrdinalIgnoreCase)));
            }
        }

        var finalList = (IReadOnlyCollection<string>)(list.Count == 0 ? Array.Empty<string>() : list.AsReadOnly());
        context.Cache.GetOrAdd("profilePaths", () => finalList);
        return finalList;
    }
}
