using Microsoft.Win32;
using ForensicScanner.Core.Models;

namespace ForensicScanner.Core.Analyzers;

public class AmcacheAnalyzer : IAnalyzer
{
    public string Name => "Amcache Parser";
    public ScanDepth RequiredDepth => ScanDepth.Medium;

    private static readonly string AmcachePath = @"C:\Windows\AppCompat\Programs\Amcache.hve";

    public Task<List<Finding>> AnalyzeAsync(ScanContext context)
    {
        var findings = new List<Finding>();

        if (!File.Exists(AmcachePath))
        {
            findings.Add(new Finding
            {
                Severity = SeverityLevel.VerySus,
                Title = "Amcache.hve Missing",
                Explanation = "Amcache.hve file not found. This may indicate manual deletion to hide execution traces.",
                ArtifactPath = AmcachePath,
                Category = "Amcache"
            });
            return Task.FromResult(findings);
        }

        try
        {
            var fileInfo = new FileInfo(AmcachePath);
            findings.Add(new Finding
            {
                Severity = SeverityLevel.Normal,
                Title = "Amcache.hve Found",
                Explanation = $"Amcache.hve exists and was last modified on {fileInfo.LastWriteTime:yyyy-MM-dd HH:mm:ss}.",
                ArtifactPath = AmcachePath,
                Category = "Amcache",
                Timestamp = fileInfo.LastWriteTime
            });

            if (fileInfo.LastWriteTime < DateTime.Now.AddDays(-30))
            {
                findings.Add(new Finding
                {
                    Severity = SeverityLevel.SlightlySus,
                    Title = "Amcache Not Recently Modified",
                    Explanation = "Amcache.hve has not been updated in over 30 days, which is unusual for an active system.",
                    ArtifactPath = AmcachePath,
                    Category = "Amcache",
                    Timestamp = fileInfo.LastWriteTime
                });
            }
        }
        catch (UnauthorizedAccessException)
        {
            findings.Add(new Finding
            {
                Severity = SeverityLevel.Normal,
                Title = "Amcache Access Denied",
                Explanation = "Unable to access Amcache.hve. File may be locked by system.",
                ArtifactPath = AmcachePath,
                Category = "Amcache"
            });
        }
        catch (Exception ex)
        {
            findings.Add(new Finding
            {
                Severity = SeverityLevel.Normal,
                Title = "Amcache Read Error",
                Explanation = $"Error accessing Amcache.hve: {ex.Message}",
                ArtifactPath = AmcachePath,
                Category = "Amcache"
            });
        }

        return Task.FromResult(findings);
    }
}
