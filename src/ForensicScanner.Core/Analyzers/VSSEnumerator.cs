using ForensicScanner.Core.Models;
using ForensicScanner.Core.Utilities;

namespace ForensicScanner.Core.Analyzers;

public class VSSEnumerator : IAnalyzer
{
    public string Name => "Volume Shadow Copy Enumerator";
    public ScanDepth RequiredDepth => ScanDepth.Deep;

    public Task<List<Finding>> AnalyzeAsync(ScanContext context)
    {
        var findings = new List<Finding>();

        try
        {
            var result = CommandExecutor.Run("vssadmin", "list shadows", timeoutSeconds: 20);

            if (!result.Succeeded)
            {
                findings.Add(new Finding
                {
                    Severity = SeverityLevel.SlightlySus,
                    Title = "VSS Enumeration Failed",
                    Explanation = "Unable to list Volume Shadow Copies. VSS may be disabled or deleted.",
                    ArtifactPath = "Volume Shadow Copy Service",
                    Category = "VSS"
                });
                return Task.FromResult(findings);
            }

            var output = result.StandardOutput;
            if (output.Contains("No items found", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new Finding
                {
                    Severity = SeverityLevel.VerySus,
                    Title = "No Volume Shadow Copies Found",
                    Explanation = "No shadow copies exist. This could indicate manual deletion to hide forensic evidence.",
                    ArtifactPath = "Volume Shadow Copy Service",
                    Category = "VSS"
                });
            }
            else
            {
                var lines = output.Split(Environment.NewLine);
                var shadowCopyCount = lines.Count(l => l.Contains("Shadow Copy ID:", StringComparison.OrdinalIgnoreCase));

                findings.Add(new Finding
                {
                    Severity = SeverityLevel.Normal,
                    Title = $"{shadowCopyCount} Volume Shadow Copies Found",
                    Explanation = $"System has {shadowCopyCount} shadow copies available for forensic analysis.",
                    ArtifactPath = "Volume Shadow Copy Service",
                    Category = "VSS"
                });
            }
        }
        catch (Exception ex)
        {
            findings.Add(new Finding
            {
                Severity = SeverityLevel.Normal,
                Title = "VSS Check Error",
                Explanation = $"Error checking Volume Shadow Copies: {ex.Message}",
                ArtifactPath = "Volume Shadow Copy Service",
                Category = "VSS"
            });
        }

        return Task.FromResult(findings);
    }
}
