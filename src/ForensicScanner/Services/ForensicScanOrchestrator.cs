using ForensicScanner.Analyzers;
using ForensicScanner.Logging;
using ForensicScanner.Models;
using ForensicScanner.Options;
using ForensicScanner.Reporting;
using ForensicScanner.Utilities;
using System.Diagnostics;

namespace ForensicScanner.Services;

public sealed class ForensicScanOrchestrator
{
    private readonly ILogger _logger;
    private readonly SystemInfoProvider _systemInfoProvider;
    private readonly IReadOnlyList<IArtifactAnalyzer> _analyzers;

    public ForensicScanOrchestrator(ILogger logger)
    {
        _logger = logger;
        _systemInfoProvider = new SystemInfoProvider();
        _analyzers = new List<IArtifactAnalyzer>
        {
            new RegistryAnalyzer(),
            new EventLogAnalyzer(),
            new RecycleBinAnalyzer(),
            new SystemLocationAnalyzer(),
            new ProcessAnalyzer()
        };
    }

    public async Task<int> RunAsync(ScanOptions options, CancellationToken token)
    {
        _logger.SetVerbose(options.Verbose);

        if (!OperatingSystem.IsWindows())
        {
            _logger.Warn("The scanner targets Windows 10/11. Some functionality will be skipped on non-Windows hosts.");
        }

        if (!SecurityUtilities.IsRunningAsAdministrator())
        {
            _logger.Warn("Administrator privileges are recommended for comprehensive access to forensic artifacts.");
        }

        var systemInfo = await _systemInfoProvider.GetAsync(token).ConfigureAwait(false);
        var cache = new ArtifactCache();
        var context = new ScanContext(options, _logger, systemInfo, cache);

        var analyzersToRun = _analyzers.Where(analyzer => options.ShouldRun(analyzer.Category)).ToList();
        if (analyzersToRun.Count == 0)
        {
            _logger.Warn("No artifact analyzers selected. Exiting.");
            return 1;
        }

        var stopwatch = Stopwatch.StartNew();

        var analyzerTasks = analyzersToRun.Select(analyzer => Task.Run(async () =>
        {
            try
            {
                token.ThrowIfCancellationRequested();
                _logger.Verbose($"Starting {analyzer.Category} analysis...");
                var findings = await analyzer.AnalyzeAsync(context, token).ConfigureAwait(false);
                _logger.Verbose($"{analyzer.Category} analysis completed ({findings.Count} findings).");
                return findings;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.Error($"{analyzer.Category} analyzer failed: {ex.Message}");
                return (IReadOnlyCollection<ForensicFinding>)Array.Empty<ForensicFinding>();
            }
        }, token)).ToList();

        IReadOnlyList<ForensicFinding> aggregated;
        try
        {
            var findingsPerAnalyzer = await Task.WhenAll(analyzerTasks).ConfigureAwait(false);
            aggregated = findingsPerAnalyzer.SelectMany(f => f).ToList();
        }
        catch (OperationCanceledException)
        {
            _logger.Warn("Scan cancelled by operator.");
            return 2;
        }

        var filtered = aggregated
            .Where(f => f.Severity >= options.MinimumSeverity)
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Timestamp ?? options.ScanTimestampUtc)
            .ToList();

        var report = new ForensicReportBuilder(systemInfo, options)
            .WithDuration(stopwatch.Elapsed)
            .WithFindings(filtered)
            .Build();

        var reportText = report.Render(options.VerboseArtifacts);
        Console.WriteLine(reportText);

        if (options.SaveReportToFile)
        {
            try
            {
                File.WriteAllText(options.OutputPath!, reportText);
                _logger.Info($"Report saved to {options.OutputPath}.");
            }
            catch (Exception ex)
            {
                _logger.Error($"Failed to save report: {ex.Message}");
            }
        }

        stopwatch.Stop();
        _logger.Info($"Scan completed in {stopwatch.Elapsed.TotalSeconds:F1}s. Total findings: {filtered.Count}.");
        return 0;
    }
}
