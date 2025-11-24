using ForensicScanner.Logging;
using ForensicScanner.Options;
using ForensicScanner.Services;

var logger = new ConsoleLogger();
var orchestrator = new ForensicScanOrchestrator(logger);
var consoleCts = new CancellationTokenSource();

Console.CancelKeyPress += (_, args) =>
{
    args.Cancel = true;
    consoleCts.Cancel();
    logger.Warn("Cancellation requested. Attempting graceful shutdown...");
};

var rootCommand = CliOptions.BuildRootCommand(async (options, token) =>
{
    using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(token, consoleCts.Token);
    return await orchestrator.RunAsync(options, linkedCts.Token).ConfigureAwait(false);
});

return await rootCommand.InvokeAsync(args);
