namespace ForensicScanner.Core.Models;

public class ScanResult
{
    public DateTime StartTime { get; set; }
    public DateTime EndTime { get; set; }
    public ScanDepth Depth { get; set; }
    public List<Finding> Findings { get; set; } = new();
    public List<string> Errors { get; set; } = new();
    public ScanStatistics Statistics { get; private set; } = new();

    public void AddFinding(Finding finding)
    {
        Findings.Add(finding);
        Statistics.Register(finding);
    }

    public void AddError(string error)
    {
        Errors.Add($"[{DateTime.Now:HH:mm:ss}] {error}");
    }

    public TimeSpan Duration => EndTime - StartTime;
}
