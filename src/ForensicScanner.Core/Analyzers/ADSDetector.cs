using ForensicScanner.Core.Models;
using ForensicScanner.Core.Utilities;

namespace ForensicScanner.Core.Analyzers;

public class ADSDetector : IAnalyzer
{
    public string Name => "Alternate Data Stream Detector";
    public ScanDepth RequiredDepth => ScanDepth.Deep;

    private static readonly string[] DefaultPaths =
    {
        @"C:\Users",
        @"C:\ProgramData",
        @"C:\Windows"
    };

    public Task<List<Finding>> AnalyzeAsync(ScanContext context)
    {
        var findings = new List<Finding>();
        var paths = context.CustomFilePaths.Count > 0 ? context.CustomFilePaths : DefaultPaths;

        foreach (var path in paths)
        {
            if (!Directory.Exists(path))
            {
                findings.Add(new Finding
                {
                    Severity = SeverityLevel.Normal,
                    Title = "Path Not Found",
                    Explanation = $"Path {path} does not exist.",
                    ArtifactPath = path,
                    Category = "ADS"
                });
                continue;
            }

            try
            {
                var command = $"/c dir /r \"{path}\"";
                var result = CommandExecutor.Run("cmd.exe", command, timeoutSeconds: 30);

                if (!result.Succeeded)
                {
                    findings.Add(new Finding
                    {
                        Severity = SeverityLevel.Normal,
                        Title = "ADS Scan Failed",
                        Explanation = $"Failed to enumerate ADS for {path}. {result.StandardError}",
                        ArtifactPath = path,
                        Category = "ADS"
                    });
                    continue;
                }

                var lines = result.StandardOutput.Split(Environment.NewLine);
                foreach (var line in lines)
                {
                    if (line.Contains(":$DATA", StringComparison.OrdinalIgnoreCase))
                    {
                        findings.Add(new Finding
                        {
                            Severity = SeverityLevel.VerySus,
                            Title = "Alternate Data Stream Found",
                            Explanation = line.Trim(),
                            ArtifactPath = path,
                            Category = "ADS"
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                findings.Add(new Finding
                {
                    Severity = SeverityLevel.Normal,
                    Title = "ADS Scan Error",
                    Explanation = $"Error while scanning {path} for ADS: {ex.Message}",
                    ArtifactPath = path,
                    Category = "ADS"
                });
            }
        }

        return Task.FromResult(findings);
    }
}
