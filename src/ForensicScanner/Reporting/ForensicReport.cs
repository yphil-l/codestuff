using ForensicScanner.Models;
using ForensicScanner.Options;
using System.Text;
using System.Linq;

namespace ForensicScanner.Reporting;

public sealed class ForensicReport
{
    private readonly IReadOnlyDictionary<Severity, int> _severityTotals;
    private readonly IReadOnlyList<string> _recommendations;

    internal ForensicReport(
        SystemInformation systemInformation,
        ScanOptions options,
        IReadOnlyList<ForensicFinding> findings,
        TimeSpan duration,
        IReadOnlyDictionary<Severity, int> severityTotals,
        IReadOnlyList<string> recommendations)
    {
        SystemInformation = systemInformation;
        Options = options;
        Findings = findings;
        Duration = duration;
        GeneratedAt = DateTimeOffset.UtcNow;
        _severityTotals = severityTotals;
        _recommendations = recommendations;
    }

    public SystemInformation SystemInformation { get; }

    public ScanOptions Options { get; }

    public IReadOnlyList<ForensicFinding> Findings { get; }

    public TimeSpan Duration { get; }

    public DateTimeOffset GeneratedAt { get; }

    public string Render(bool includeVerboseArtifacts)
    {
        var builder = new StringBuilder();
        builder.AppendLine("==============================");
        builder.AppendLine(" Automated Forensic Scan Report");
        builder.AppendLine("==============================");
        builder.AppendLine($"Generated: {GeneratedAt.LocalDateTime}");
        builder.AppendLine($"Duration : {Duration.TotalSeconds:F1}s");
        builder.AppendLine();

        builder.AppendLine("System Information");
        builder.AppendLine("-------------------");
        builder.AppendLine($"Host        : {SystemInformation.MachineName}");
        builder.AppendLine($"User        : {SystemInformation.Domain}\\{SystemInformation.UserName}");
        builder.AppendLine($"OS          : {SystemInformation.OsDescription} ({SystemInformation.WindowsEdition})");
        builder.AppendLine($"Architecture: {(SystemInformation.Is64BitOperatingSystem ? "64-bit" : "32-bit")}");
        builder.AppendLine($"Admin       : {(SystemInformation.IsAdministrator ? "Yes" : "No")}");
        if (SystemInformation.LastBootTime is { } boot)
        {
            builder.AppendLine($"Last Boot   : {boot.LocalDateTime}");
        }
        if (SystemInformation.Uptime is { } uptime)
        {
            builder.AppendLine($"Uptime      : {uptime:c}");
        }
        builder.AppendLine();

        builder.AppendLine("Scan Configuration");
        builder.AppendLine("-------------------");
        builder.AppendLine($"Artifacts   : {Options}");
        builder.AppendLine($"Severity    : {Options.MinimumSeverity.ToFriendlyName()} minimum");
        builder.AppendLine($"Verbose     : {Options.Verbose}");
        builder.AppendLine($"Deep memory : {Options.DeepMemoryAnalysis}");
        builder.AppendLine();

        builder.AppendLine("Findings by Category");
        builder.AppendLine("---------------------");
        if (Findings.Count == 0)
        {
            builder.AppendLine("No findings met the selected severity threshold.");
        }
        else
        {
            foreach (var group in Findings.GroupBy(f => f.Category))
            {
                builder.AppendLine($"{group.Key} ({group.Count()} findings)");
                foreach (var finding in group)
                {
                    builder.AppendLine(" - " + finding.ToDisplayString(includeVerboseArtifacts));
                }
                builder.AppendLine();
            }
        }

        builder.AppendLine("Severity Summary");
        builder.AppendLine("----------------");
        foreach (Severity severity in Enum.GetValues(typeof(Severity)))
        {
            _severityTotals.TryGetValue(severity, out var count);
            builder.AppendLine($"{severity.ToFriendlyName(),-9}: {count}");
        }
        builder.AppendLine();

        builder.AppendLine("Recommendations");
        builder.AppendLine("----------------");
        if (_recommendations.Count == 0)
        {
            builder.AppendLine("- Continue monitoring; no immediate escalations recommended.");
        }
        else
        {
            foreach (var recommendation in _recommendations)
            {
                builder.AppendLine("- " + recommendation);
            }
        }
        builder.AppendLine();

        builder.AppendLine("Timeline");
        builder.AppendLine("--------");
        var timeline = Findings
            .Where(f => f.Timestamp.HasValue)
            .OrderBy(f => f.Timestamp)
            .Take(200)
            .ToList();

        if (timeline.Count == 0)
        {
            builder.AppendLine("No timestamped findings available.");
        }
        else
        {
            foreach (var item in timeline)
            {
                builder.AppendLine($"{item.Timestamp:yyyy-MM-dd HH:mm:ss} | {item.Severity.ToFriendlyName(),-8} | {item.Description}");
            }
        }

        builder.AppendLine();
        builder.AppendLine("End of report");
        return builder.ToString();
    }
}

public sealed class ForensicReportBuilder
{
    private readonly SystemInformation _systemInformation;
    private readonly ScanOptions _options;
    private TimeSpan _duration;
    private IReadOnlyList<ForensicFinding> _findings = Array.Empty<ForensicFinding>();

    public ForensicReportBuilder(SystemInformation systemInformation, ScanOptions options)
    {
        _systemInformation = systemInformation;
        _options = options;
    }

    public ForensicReportBuilder WithDuration(TimeSpan duration)
    {
        _duration = duration;
        return this;
    }

    public ForensicReportBuilder WithFindings(IReadOnlyList<ForensicFinding> findings)
    {
        _findings = findings;
        return this;
    }

    public ForensicReport Build()
    {
        var severityTotals = Enum.GetValues(typeof(Severity))
            .Cast<Severity>()
            .ToDictionary(severity => severity, severity => _findings.Count(f => f.Severity == severity));

        var recommendations = BuildRecommendations(_findings);

        return new ForensicReport(
            _systemInformation,
            _options,
            _findings,
            _duration,
            severityTotals,
            recommendations);
    }

    private static IReadOnlyList<string> BuildRecommendations(IReadOnlyCollection<ForensicFinding> findings)
    {
        var recs = new List<string>();

        if (findings.Any(f => f.Description.Contains("log clearing", StringComparison.OrdinalIgnoreCase)))
        {
            recs.Add("Event log clearing detected; immediately preserve remaining logs and correlate with user activity.");
        }

        if (findings.Any(f => f.Description.Contains("disabled", StringComparison.OrdinalIgnoreCase) && f.Category == ArtifactCategory.Registry))
        {
            recs.Add("Re-enable impacted Windows security features (Defender, Windows Firewall, SmartScreen) and review tampering source.");
        }

        if (findings.Any(f => f.Category == ArtifactCategory.Processes && f.Severity >= Severity.High))
        {
            recs.Add("Capture memory dumps of the flagged processes and search for injected modules or malicious strings.");
        }

        if (findings.Any(f => f.Category == ArtifactCategory.RecycleBin && f.Severity >= Severity.High))
        {
            recs.Add("Recover deleted files from the Recycle Bin or shadow copies before they are overwritten.");
        }

        if (!recs.Any())
        {
            recs.Add("No critical indicators detected. Maintain monitoring and re-run the scanner if new alerts arise.");
        }

        return recs;
    }
}
