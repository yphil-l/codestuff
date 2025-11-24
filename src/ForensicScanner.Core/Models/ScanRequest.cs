namespace ForensicScanner.Core.Models;

public class ScanRequest
{
    public ScanDepth Depth { get; init; } = ScanDepth.Light;
    public IReadOnlyCollection<string> CustomRegistryKeys { get; init; } = Array.Empty<string>();
    public IReadOnlyCollection<string> CustomFilePaths { get; init; } = Array.Empty<string>();
    public string? ReportOutputPath { get; init; }
    public bool SaveReportToFile => !string.IsNullOrWhiteSpace(ReportOutputPath);
    public bool AppendTimestampToReport { get; init; } = true;
}
