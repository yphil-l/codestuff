using Microsoft.Win32;
using ForensicScanner.Core.Models;

namespace ForensicScanner.Core.Analyzers;

public class UserAssistAnalyzer : IAnalyzer
{
    public string Name => "UserAssist Analyzer";
    public ScanDepth RequiredDepth => ScanDepth.Medium;

    private static readonly string UserAssistKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

    public Task<List<Finding>> AnalyzeAsync(ScanContext context)
    {
        var findings = new List<Finding>();

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(UserAssistKeyPath);
            if (key == null)
            {
                findings.Add(new Finding
                {
                    Severity = SeverityLevel.VerySus,
                    Title = "UserAssist Key Missing",
                    Explanation = "UserAssist registry key not found. May have been deleted to hide execution history.",
                    ArtifactPath = $@"HKCU\{UserAssistKeyPath}",
                    Category = "UserAssist"
                });
                return Task.FromResult(findings);
            }

            foreach (var guidName in key.GetSubKeyNames())
            {
                using var guidKey = key.OpenSubKey($@"{guidName}\Count");
                if (guidKey == null) continue;

                var valueNames = guidKey.GetValueNames();
                findings.Add(new Finding
                {
                    Severity = SeverityLevel.Normal,
                    Title = $"UserAssist GUID {guidName}",
                    Explanation = $"Found {valueNames.Length} execution entries in UserAssist.",
                    ArtifactPath = $@"HKCU\{UserAssistKeyPath}\{guidName}\Count",
                    Category = "UserAssist"
                });
            }
        }
        catch (Exception ex)
        {
            findings.Add(new Finding
            {
                Severity = SeverityLevel.Normal,
                Title = "UserAssist Read Error",
                Explanation = $"Error reading UserAssist registry: {ex.Message}",
                ArtifactPath = $@"HKCU\{UserAssistKeyPath}",
                Category = "UserAssist"
            });
        }

        return Task.FromResult(findings);
    }
}
