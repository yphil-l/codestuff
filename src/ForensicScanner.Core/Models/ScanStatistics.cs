namespace ForensicScanner.Core.Models;

public class ScanStatistics
{
    public int NormalCount { get; set; }
    public int SlightlySusCount { get; set; }
    public int VerySusCount { get; set; }
    public int CheatCount { get; set; }

    public void Register(Finding finding)
    {
        switch (finding.Severity)
        {
            case SeverityLevel.Normal:
                NormalCount++;
                break;
            case SeverityLevel.SlightlySus:
                SlightlySusCount++;
                break;
            case SeverityLevel.VerySus:
                VerySusCount++;
                break;
            case SeverityLevel.Cheat:
                CheatCount++;
                break;
        }
    }

    public override string ToString()
        => $"Normal: {NormalCount} | Slightly Sus: {SlightlySusCount} | Very Sus: {VerySusCount} | CHEAT: {CheatCount}";
}
