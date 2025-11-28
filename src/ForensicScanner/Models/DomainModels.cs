using System.Text;

namespace ForensicScanner.Models;

public enum Severity
{
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3
}

public enum ArtifactCategory
{
    Registry,
    EventLogs,
    RecycleBin,
    SystemLocations,
    Processes
}

public sealed class ForensicFinding
{
    public ForensicFinding(
        Severity severity,
        ArtifactCategory category,
        string description,
        string? location = null,
        DateTimeOffset? timestamp = null,
        string? context = null,
        string? referenceId = null)
    {
        Severity = severity;
        Category = category;
        Description = description;
        Location = location;
        Timestamp = timestamp;
        Context = context;
        ReferenceId = referenceId;
    }

    public Severity Severity { get; }

    public ArtifactCategory Category { get; }

    public string Description { get; }

    public string? Location { get; }

    public DateTimeOffset? Timestamp { get; }

    public string? Context { get; }

    public string? ReferenceId { get; }

    public string ToDisplayString(bool includeContext)
    {
        var builder = new StringBuilder();
        builder.Append('[')
            .Append(Severity)
            .Append("] ")
            .Append(Category)
            .Append(':')
            .Append(' ')
            .Append(Description);

        if (!string.IsNullOrWhiteSpace(Location))
        {
            builder.Append(" | Location: ")
                   .Append(Location);
        }

        if (Timestamp is { } ts)
        {
            builder.Append(" | Timestamp: ")
                   .Append(ts.LocalDateTime);
        }

        if (!string.IsNullOrWhiteSpace(ReferenceId))
        {
            builder.Append(" | Evidence: ")
                   .Append(ReferenceId);
        }

        if (includeContext && !string.IsNullOrWhiteSpace(Context))
        {
            builder.AppendLine()
                   .Append("    Context: ")
                   .Append(Context);
        }

        return builder.ToString();
    }
}

public sealed record SystemInformation(
    string MachineName,
    string UserName,
    string Domain,
    string OsDescription,
    bool Is64BitOperatingSystem,
    bool IsAdministrator,
    DateTimeOffset? LastBootTime,
    TimeSpan? Uptime,
    string? WindowsEdition,
    string? Culture,
    string? TimeZoneDisplay,
    string? ProcessorArchitecture);

public static class SeverityExtensions
{
    public static Severity ParseMinimumSeverity(bool criticalOnly, bool highAndAbove)
    {
        if (criticalOnly)
        {
            return Severity.Critical;
        }

        if (highAndAbove)
        {
            return Severity.High;
        }

        return Severity.Low;
    }

    public static string ToFriendlyName(this Severity severity) => severity switch
    {
        Severity.Critical => "CRITICAL",
        Severity.High => "HIGH",
        Severity.Medium => "MEDIUM",
        Severity.Low => "LOW",
        _ => severity.ToString().ToUpperInvariant()
    };
}
