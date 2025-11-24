using ForensicScanner.Models;
using System.CommandLine;

namespace ForensicScanner.Options;

public sealed class ScanOptions
{
    public bool IncludeRegistry { get; init; }
    public bool IncludeEventLogs { get; init; }
    public bool IncludeRecycleBin { get; init; }
    public bool IncludeSystemLocations { get; init; }
    public bool IncludeProcesses { get; init; }
    public bool Verbose { get; init; }
    public bool DeepMemoryAnalysis { get; init; }
    public Severity MinimumSeverity { get; init; } = Severity.Low;
    public IReadOnlyList<string> TargetUserSids { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> CustomPaths { get; init; } = Array.Empty<string>();
    public string? OutputPath { get; init; }
    public TimeSpan EventLogLookback { get; init; } = TimeSpan.FromHours(168);
    public DateTimeOffset ScanTimestampUtc { get; init; } = DateTimeOffset.UtcNow;
    public bool VerboseArtifacts { get; init; }

    public bool SaveReportToFile => !string.IsNullOrWhiteSpace(OutputPath);

    public bool ShouldRun(ArtifactCategory category) => category switch
    {
        ArtifactCategory.Registry => IncludeRegistry,
        ArtifactCategory.EventLogs => IncludeEventLogs,
        ArtifactCategory.RecycleBin => IncludeRecycleBin,
        ArtifactCategory.SystemLocations => IncludeSystemLocations,
        ArtifactCategory.Processes => IncludeProcesses,
        _ => false
    };

    public override string ToString() =>
        $"Artifacts => Registry:{IncludeRegistry}, EventLogs:{IncludeEventLogs}, RecycleBin:{IncludeRecycleBin}, System:{IncludeSystemLocations}, Processes:{IncludeProcesses} | Verbose:{Verbose} | DeepMemory:{DeepMemoryAnalysis} | MinSeverity:{MinimumSeverity}";
}

public static class CliOptions
{
    private static readonly Option<bool> AllOption = new("--all", description: "Scan every artifact category.");
    private static readonly Option<bool> RegistryOption = new("--registry", description: "Scan Windows registry artifacts.");
    private static readonly Option<bool> EventLogsOption = new("--events", description: "Scan Windows event logs.");
    private static readonly Option<bool> RecycleOption = new("--recycle", description: "Analyze Recycle Bin artifacts.");
    private static readonly Option<bool> SystemOption = new("--system", description: "Audit system locations (tasks, PCA, PowerShell history, custom paths).");
    private static readonly Option<bool> ProcessOption = new("--processes", description: "Inspect running processes, modules, and network connections.");
    private static readonly Option<bool> VerboseOption = new("--verbose", description: "Enable verbose artifact logging.");
    private static readonly Option<bool> VerboseArtifactsOption = new("--verbose-artifacts", description: "Include verbose per-artifact listings in the report.");
    private static readonly Option<bool> DeepMemoryOption = new("--deep-memory", description: "Enable aggressive memory string scanning (slower).");
    private static readonly Option<bool> CriticalOnlyOption = new("--critical-only", description: "Only include CRITICAL findings in the report.");
    private static readonly Option<bool> HighAndAboveOption = new("--high-and-above", description: "Only include HIGH and CRITICAL findings.");
    private static readonly Option<FileInfo?> OutputOption = new(new[] { "--output", "-o" }, description: "Save the generated report to the specified path.");
    private static readonly Option<string[]> UserSidOption = new("--user-sid", description: "Limit scans to one or more specific user SIDs.")
    {
        AllowMultipleArgumentsPerToken = true,
        Arity = ArgumentArity.ZeroOrMore
    };
    private static readonly Option<string[]> CustomPathOption = new("--custom-path", description: "Include additional custom paths to scan for suspicious binaries.")
    {
        AllowMultipleArgumentsPerToken = true,
        Arity = ArgumentArity.ZeroOrMore
    };
    private static readonly Option<int> LookbackOption = new("--event-lookback-hours", () => 168, "Number of hours of event logs to inspect.");

    static CliOptions()
    {
        UserSidOption.SetDefaultValue(Array.Empty<string>());
        CustomPathOption.SetDefaultValue(Array.Empty<string>());
    }

    public static RootCommand BuildRootCommand(Func<ScanOptions, CancellationToken, Task<int>> handler)
    {
        var root = new RootCommand("Automated Windows Forensic Scanner - comprehensive anti-cheat artifact triage.");

        root.AddOption(AllOption);
        root.AddOption(RegistryOption);
        root.AddOption(EventLogsOption);
        root.AddOption(RecycleOption);
        root.AddOption(SystemOption);
        root.AddOption(ProcessOption);
        root.AddOption(VerboseOption);
        root.AddOption(VerboseArtifactsOption);
        root.AddOption(DeepMemoryOption);
        root.AddOption(CriticalOnlyOption);
        root.AddOption(HighAndAboveOption);
        root.AddOption(OutputOption);
        root.AddOption(UserSidOption);
        root.AddOption(CustomPathOption);
        root.AddOption(LookbackOption);

        root.SetHandler(async context =>
        {
            var token = context.GetCancellationToken();
            var options = BuildOptions(context.ParseResult);
            var exitCode = await handler(options, token).ConfigureAwait(false);
            context.ExitCode = exitCode;
        });

        return root;
    }

    private static ScanOptions BuildOptions(ParseResult parseResult)
    {
        bool registry = parseResult.GetValueForOption(RegistryOption);
        bool events = parseResult.GetValueForOption(EventLogsOption);
        bool recycle = parseResult.GetValueForOption(RecycleOption);
        bool system = parseResult.GetValueForOption(SystemOption);
        bool processes = parseResult.GetValueForOption(ProcessOption);
        bool all = parseResult.GetValueForOption(AllOption);

        var artifactFlags = new[] { registry, events, recycle, system, processes };
        bool anyExplicit = artifactFlags.Any(flag => flag);

        if (all || !anyExplicit)
        {
            registry = events = recycle = system = processes = true;
        }

        var userSids = parseResult.GetValueForOption(UserSidOption) ?? Array.Empty<string>();
        var customPaths = parseResult.GetValueForOption(CustomPathOption) ?? Array.Empty<string>();
        var outputInfo = parseResult.GetValueForOption(OutputOption);
        var criticalOnly = parseResult.GetValueForOption(CriticalOnlyOption);
        var highAndAbove = parseResult.GetValueForOption(HighAndAboveOption);
        var verbose = parseResult.GetValueForOption(VerboseOption);
        var verboseArtifacts = parseResult.GetValueForOption(VerboseArtifactsOption);
        var deepMemory = parseResult.GetValueForOption(DeepMemoryOption);
        var lookbackHours = parseResult.GetValueForOption(LookbackOption);

        var minSeverity = SeverityExtensions.ParseMinimumSeverity(criticalOnly, highAndAbove);

        return new ScanOptions
        {
            IncludeRegistry = registry,
            IncludeEventLogs = events,
            IncludeRecycleBin = recycle,
            IncludeSystemLocations = system,
            IncludeProcesses = processes,
            Verbose = verbose,
            VerboseArtifacts = verboseArtifacts,
            DeepMemoryAnalysis = deepMemory,
            MinimumSeverity = minSeverity,
            TargetUserSids = userSids.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            CustomPaths = customPaths.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            OutputPath = outputInfo?.FullName,
            EventLogLookback = TimeSpan.FromHours(Math.Clamp(lookbackHours, 1, 24 * 14)),
            ScanTimestampUtc = DateTimeOffset.UtcNow
        };
    }
}
