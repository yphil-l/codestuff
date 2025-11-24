using ForensicScanner.Core.Models;

namespace ForensicScanner.Core.Analyzers;

public class CustomArtifactAnalyzer : IAnalyzer
{
    public string Name => "Custom Artifact Detector";
    public ScanDepth RequiredDepth => ScanDepth.Light;

    public Task<List<Finding>> AnalyzeAsync(ScanContext context)
    {
        var findings = new List<Finding>();

        foreach (var filePath in context.CustomFilePaths)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    var info = new FileInfo(filePath);
                    findings.Add(new Finding
                    {
                        Severity = SeverityLevel.Normal,
                        Title = $"Custom File Exists: {Path.GetFileName(filePath)}",
                        Explanation = $"File found. Size: {info.Length} bytes. Last modified: {info.LastWriteTime}",
                        ArtifactPath = filePath,
                        Category = "Custom Files"
                    });
                }
                else if (Directory.Exists(filePath))
                {
                    var dirInfo = new DirectoryInfo(filePath);
                    findings.Add(new Finding
                    {
                        Severity = SeverityLevel.Normal,
                        Title = $"Custom Directory Exists: {dirInfo.Name}",
                        Explanation = $"Directory contains {dirInfo.GetFileSystemInfos().Length} items.",
                        ArtifactPath = filePath,
                        Category = "Custom Files"
                    });
                }
                else
                {
                    findings.Add(new Finding
                    {
                        Severity = SeverityLevel.VerySus,
                        Title = "Custom Path Missing",
                        Explanation = $"Custom path {filePath} does not exist. May have been deleted.",
                        ArtifactPath = filePath,
                        Category = "Custom Files"
                    });
                }
            }
            catch (Exception ex)
            {
                findings.Add(new Finding
                {
                    Severity = SeverityLevel.Normal,
                    Title = "Custom Path Error",
                    Explanation = $"Error accessing custom path {filePath}: {ex.Message}",
                    ArtifactPath = filePath,
                    Category = "Custom Files"
                });
            }
        }

        return Task.FromResult(findings);
    }
}
