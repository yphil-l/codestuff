using ForensicScanner.Core.Models;
using ForensicScanner.Core.Utilities;

namespace ForensicScanner.Core.Analyzers;

public class USNJournalAnalyzer : IAnalyzer
{
    public string Name => "USN Journal Reader";
    public ScanDepth RequiredDepth => ScanDepth.Medium;

    public Task<List<Finding>> AnalyzeAsync(ScanContext context)
    {
        var findings = new List<Finding>();

        try
        {
            var result = CommandExecutor.Run("fsutil", "usn queryjournal C:", timeoutSeconds: 10);

            if (!result.Succeeded)
            {
                findings.Add(new Finding
                {
                    Severity = SeverityLevel.VerySus,
                    Title = "USN Journal Query Failed",
                    Explanation = "Unable to query USN Journal on C: drive. May have been deleted or disabled.",
                    ArtifactPath = "C: USN Journal",
                    Category = "USN Journal"
                });
                return Task.FromResult(findings);
            }

            var output = result.StandardOutput;

            if (output.Contains("disabled", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new Finding
                {
                    Severity = SeverityLevel.Cheat,
                    Title = "USN Journal Disabled",
                    Explanation = "USN Journal is disabled. This is highly suspicious as it prevents tracking file operations.",
                    ArtifactPath = "C: USN Journal",
                    Category = "USN Journal"
                });
            }
            else if (output.Contains("Maximum Size", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new Finding
                {
                    Severity = SeverityLevel.Normal,
                    Title = "USN Journal Active",
                    Explanation = "USN Journal is active and tracking file system changes.",
                    ArtifactPath = "C: USN Journal",
                    Category = "USN Journal"
                });
            }
        }
        catch (Exception ex)
        {
            findings.Add(new Finding
            {
                Severity = SeverityLevel.Normal,
                Title = "USN Journal Check Error",
                Explanation = $"Error checking USN Journal: {ex.Message}",
                ArtifactPath = "C: USN Journal",
                Category = "USN Journal"
            });
        }

        return Task.FromResult(findings);
    }
}
