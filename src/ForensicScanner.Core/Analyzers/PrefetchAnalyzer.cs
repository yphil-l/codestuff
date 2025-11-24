using ForensicScanner.Core.Models;

namespace ForensicScanner.Core.Analyzers;

public class PrefetchAnalyzer : IAnalyzer
{
    public string Name => "Prefetch Parser";
    public ScanDepth RequiredDepth => ScanDepth.Light;

    private static readonly string PrefetchDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
    private static readonly string[] CriticalProcesses = { "javaw.exe", "explorer.exe", "csrss.exe" };

    public Task<List<Finding>> AnalyzeAsync(ScanContext context)
    {
        var findings = new List<Finding>();

        if (!Directory.Exists(PrefetchDirectory))
        {
            findings.Add(new Finding
            {
                Severity = SeverityLevel.Normal,
                Title = "Prefetch Directory Missing",
                Explanation = "Unable to locate C:\\Windows\\Prefetch. Prefetch may be disabled.",
                ArtifactPath = PrefetchDirectory,
                Category = "Prefetch"
            });
            return Task.FromResult(findings);
        }

        AnalyzePrefetchFiles(findings);
        AnalyzeMissingPrefetch(findings);

        return Task.FromResult(findings);
    }

    private void AnalyzePrefetchFiles(List<Finding> findings)
    {
        var files = Directory.GetFiles(PrefetchDirectory, "*.pf");
        var suspicious = files.Select(file => new FileInfo(file))
                              .Where(info => info.CreationTime >= DateTime.Now.AddDays(-1))
                              .OrderByDescending(f => f.CreationTime)
                              .Take(10)
                              .ToList();

        foreach (var file in suspicious)
        {
            findings.Add(new Finding
            {
                Severity = SeverityLevel.SlightlySus,
                Title = "Recent Prefetch Entry",
                Explanation = $"Prefetch file {file.Name} was created or modified recently indicating execution.",
                ArtifactPath = file.FullName,
                Category = "Prefetch",
                Timestamp = file.LastWriteTime
            });
        }
    }

    private void AnalyzeMissingPrefetch(List<Finding> findings)
    {
        foreach (var process in CriticalProcesses)
        {
            var pattern = process.ToUpperInvariant().Replace(".EXE", string.Empty);
            var exists = Directory.EnumerateFiles(PrefetchDirectory, "*.pf")
                .Any(file => Path.GetFileName(file).StartsWith(pattern, StringComparison.OrdinalIgnoreCase));

            if (!exists)
            {
                findings.Add(new Finding
                {
                    Severity = SeverityLevel.VerySus,
                    Title = "Missing Prefetch Entry",
                    Explanation = $"Prefetch for {process} missing. This may indicate prefetch clearing or disabled prefetch.",
                    ArtifactPath = PrefetchDirectory,
                    Category = "Prefetch"
                });
            }
        }
    }
}
