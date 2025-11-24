using Microsoft.Win32;
using ForensicScanner.Core.Models;

namespace ForensicScanner.Core.Analyzers;

public class BAMAnalyzer : IAnalyzer
{
    public string Name => "BAM (Background Activity Moderator) Analyzer";
    public ScanDepth RequiredDepth => ScanDepth.Medium;

    private static readonly string BAMKeyPath = @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings";

    public Task<List<Finding>> AnalyzeAsync(ScanContext context)
    {
        var findings = new List<Finding>();

        try
        {
            using var bamKey = Registry.LocalMachine.OpenSubKey(BAMKeyPath);
            if (bamKey == null)
            {
                findings.Add(new Finding
                {
                    Severity = SeverityLevel.Normal,
                    Title = "BAM Registry Key Not Found",
                    Explanation = "BAM key not found in registry. May be disabled or system incompatible.",
                    ArtifactPath = $@"HKLM\{BAMKeyPath}",
                    Category = "BAM"
                });
                return Task.FromResult(findings);
            }

            foreach (var userSid in bamKey.GetSubKeyNames())
            {
                using var userKey = bamKey.OpenSubKey(userSid);
                if (userKey == null) continue;

                foreach (var valueName in userKey.GetValueNames())
                {
                    if (string.IsNullOrWhiteSpace(valueName)) continue;

                    var severity = AnalyzeBamEntry(valueName);
                    findings.Add(new Finding
                    {
                        Severity = severity,
                        Title = $"BAM Entry: {Path.GetFileName(valueName)}",
                        Explanation = $"Execution tracked for {valueName}",
                        ArtifactPath = $@"HKLM\{BAMKeyPath}\{userSid}\{valueName}",
                        Category = "BAM"
                    });
                }
            }
        }
        catch (Exception ex)
        {
            findings.Add(new Finding
            {
                Severity = SeverityLevel.Normal,
                Title = "BAM Read Error",
                Explanation = $"Error reading BAM registry: {ex.Message}",
                ArtifactPath = $@"HKLM\{BAMKeyPath}",
                Category = "BAM"
            });
        }

        return Task.FromResult(findings);
    }

    private SeverityLevel AnalyzeBamEntry(string path)
    {
        var lowerPath = path.ToLowerInvariant();

        if (lowerPath.Contains("temp") || lowerPath.Contains("appdata\\local\\temp"))
            return SeverityLevel.VerySus;
        if (lowerPath.Contains("powershell") || lowerPath.Contains("cmd.exe"))
            return SeverityLevel.SlightlySus;
        if (!File.Exists(path))
            return SeverityLevel.SlightlySus;

        return SeverityLevel.Normal;
    }
}
