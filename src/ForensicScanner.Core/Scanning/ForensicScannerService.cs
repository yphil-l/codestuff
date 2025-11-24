using ForensicScanner.Core.Analyzers;
using ForensicScanner.Core.Models;

namespace ForensicScanner.Core.Scanning;

public class ForensicScannerService
{
    private readonly List<IAnalyzer> _analyzers;

    public ForensicScannerService()
    {
        _analyzers = new List<IAnalyzer>
        {
            new EventLogAnalyzer(),
            new PrefetchAnalyzer(),
            new RegistryAnalyzer(),
            new QuickMemoryAnalyzer(),
            new AmcacheAnalyzer(),
            new USNJournalAnalyzer(),
            new TaskSchedulerAnalyzer(),
            new BAMAnalyzer(),
            new UserAssistAnalyzer(),
            new ADSDetector(),
            new VSSEnumerator(),
            new ProcessMemoryAnalyzer(),
            new CustomArtifactAnalyzer()
        };
    }

    public event EventHandler<ProgressEventArgs>? ProgressChanged;

    public async Task<ScanResult> ScanAsync(ScanRequest request, CancellationToken cancellationToken = default)
    {
        var result = new ScanResult
        {
            StartTime = DateTime.Now,
            Depth = request.Depth
        };

        var context = new ScanContext(request, cancellationToken);

        var applicableAnalyzers = _analyzers
            .Where(a => a.RequiredDepth <= request.Depth)
            .ToList();

        var totalAnalyzers = applicableAnalyzers.Count;
        var completedAnalyzers = 0;

        foreach (var analyzer in applicableAnalyzers)
        {
            if (cancellationToken.IsCancellationRequested)
                break;

            try
            {
                ReportProgress($"Running {analyzer.Name}...", completedAnalyzers, totalAnalyzers);

                var findings = await analyzer.AnalyzeAsync(context);
                foreach (var finding in findings)
                {
                    result.AddFinding(finding);
                }
            }
            catch (Exception ex)
            {
                result.AddError($"{analyzer.Name} failed: {ex.Message}");
            }

            completedAnalyzers++;
        }

        result.EndTime = DateTime.Now;
        ReportProgress("Scan complete", totalAnalyzers, totalAnalyzers);

        return result;
    }

    private void ReportProgress(string message, int completed, int total)
    {
        ProgressChanged?.Invoke(this, new ProgressEventArgs
        {
            Message = message,
            CompletedAnalyzers = completed,
            TotalAnalyzers = total
        });
    }
}

public class ProgressEventArgs : EventArgs
{
    public string Message { get; init; } = string.Empty;
    public int CompletedAnalyzers { get; init; }
    public int TotalAnalyzers { get; init; }
    public int PercentComplete => TotalAnalyzers > 0 ? (CompletedAnalyzers * 100) / TotalAnalyzers : 0;
}
