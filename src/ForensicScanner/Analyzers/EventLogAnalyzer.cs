using ForensicScanner.Models;
using ForensicScanner.Services;
using ForensicScanner.Utilities;
using System.Collections.ObjectModel;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.ServiceProcess;
using System.Text;

namespace ForensicScanner.Analyzers;

public sealed class EventLogAnalyzer : IArtifactAnalyzer
{
    private const int MaxEventsPerLog = 200;

    public ArtifactCategory Category => ArtifactCategory.EventLogs;

    public Task<IReadOnlyCollection<ForensicFinding>> AnalyzeAsync(ScanContext context, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            context.Logger.Warn("Event log analysis is only available on Windows hosts.");
            return Task.FromResult<IReadOnlyCollection<ForensicFinding>>(Array.Empty<ForensicFinding>());
        }

        var findings = new List<ForensicFinding>();
        VerifyEventLogService(context, findings);

        var lookbackMs = Math.Max(1, (long)context.Options.EventLogLookback.TotalMilliseconds);

        AnalyzeSecurityLog(context, findings, lookbackMs, cancellationToken);
        AnalyzeSystemLog(context, findings, lookbackMs, cancellationToken);
        AnalyzeApplicationLog(context, findings, lookbackMs, cancellationToken);
        AnalyzeSetupLog(context, findings, lookbackMs, cancellationToken);
        AnalyzeTaskSchedulerLog(context, findings, lookbackMs, cancellationToken);
        AnalyzePowerShellLog(context, findings, lookbackMs, cancellationToken);

        return Task.FromResult<IReadOnlyCollection<ForensicFinding>>(new ReadOnlyCollection<ForensicFinding>(findings));
    }

    private static void VerifyEventLogService(ScanContext context, ICollection<ForensicFinding> findings)
    {
        try
        {
            using var controller = new ServiceController("eventlog");
            if (controller.Status != ServiceControllerStatus.Running)
            {
                findings.Add(new ForensicFinding(
                    Severity.Critical,
                    ArtifactCategory.EventLogs,
                    "Windows Event Log service is not running",
                    "Service: eventlog",
                    context.Options.ScanTimestampUtc,
                    controller.Status.ToString()));
            }
        }
        catch (Exception ex)
        {
            context.Logger.Verbose($"Unable to verify eventlog service: {ex.Message}");
        }
    }

    private static void AnalyzeSecurityLog(ScanContext context, ICollection<ForensicFinding> findings, long lookbackMs, CancellationToken token)
    {
        var eventMap = new Dictionary<int, (Severity Severity, string Description)>
        {
            { 4625, (Severity.High, "Failed logon attempt") },
            { 4624, (Severity.Low, "Successful logon") },
            { 1102, (Severity.Critical, "Security log was cleared") },
            { 4616, (Severity.High, "System time was changed") },
            { 4720, (Severity.High, "User account created") },
            { 4726, (Severity.High, "User account deleted") },
            { 4719, (Severity.High, "System audit policy changed") },
            { 4732, (Severity.Medium, "User added to privileged group") }
        };

        var ids = string.Join(" or ", eventMap.Keys.Select(id => $"EventID={id}"));
        var query = $"*[System[TimeCreated[timediff(@SystemTime) <= {lookbackMs}] and ({ids})]]";
        ProcessLog(context, "Security", query, token, record =>
        {
            if (!eventMap.TryGetValue(record.Id, out var meta))
            {
                return;
            }

            var timestamp = ResolveTimestamp(record, context.Options.ScanTimestampUtc);
            var severity = meta.Severity;
            var description = meta.Description;
            var extra = TryFormatDescription(record);

            if (record.Id == 1102 && timestamp > DateTimeOffset.UtcNow.AddHours(-4))
            {
                severity = Severity.Critical;
                description = "Security log clearing detected";
            }

            var finding = new ForensicFinding(
                severity,
                ArtifactCategory.EventLogs,
                description,
                $"Security Event ID {record.Id}",
                timestamp,
                extra);

            findings.Add(finding);
        });
    }

    private static void AnalyzeSystemLog(ScanContext context, ICollection<ForensicFinding> findings, long lookbackMs, CancellationToken token)
    {
        var ids = new[] { 7036, 7040, 7045, 104, 4616 };
        var eventDescriptions = new Dictionary<int, (Severity, string)>
        {
            { 7036, (Severity.Medium, "Service state changed") },
            { 7040, (Severity.High, "Service start type modified") },
            { 7045, (Severity.High, "New service installed") },
            { 104, (Severity.Critical, "Event log cleared (System log)") },
            { 4616, (Severity.High, "System time change (system log)") }
        };

        var filter = string.Join(" or ", ids.Select(id => $"EventID={id}"));
        var query = $"*[System[TimeCreated[timediff(@SystemTime) <= {lookbackMs}] and ({filter})]]";
        ProcessLog(context, "System", query, token, record =>
        {
            if (!eventDescriptions.TryGetValue(record.Id, out var meta))
            {
                return;
            }

            var timestamp = ResolveTimestamp(record, context.Options.ScanTimestampUtc);
            var desc = TryFormatDescription(record);
            var severity = meta.Item1;
            if (record.Id == 104 && timestamp > DateTimeOffset.UtcNow.AddHours(-2))
            {
                severity = Severity.Critical;
            }

            findings.Add(new ForensicFinding(
                severity,
                ArtifactCategory.EventLogs,
                meta.Item2,
                $"System Event ID {record.Id}",
                timestamp,
                desc));
        });
    }

    private static void AnalyzeApplicationLog(ScanContext context, ICollection<ForensicFinding> findings, long lookbackMs, CancellationToken token)
    {
        var query = $"*[System[TimeCreated[timediff(@SystemTime) <= {lookbackMs}] and (Level=1 or Level=2 or Level=3)]]";
        ProcessLog(context, "Application", query, token, record =>
        {
            var description = TryFormatDescription(record);
            if (!KeywordCatalog.ContainsCheatIndicator(description))
            {
                return;
            }

            var timestamp = ResolveTimestamp(record, context.Options.ScanTimestampUtc);
            findings.Add(new ForensicFinding(
                Severity.Medium,
                ArtifactCategory.EventLogs,
                "Application log reports suspicious activity",
                $"Application Event ID {record.Id}",
                timestamp,
                description));
        });
    }

    private static void AnalyzeSetupLog(ScanContext context, ICollection<ForensicFinding> findings, long lookbackMs, CancellationToken token)
    {
        var query = $"*[System[TimeCreated[timediff(@SystemTime) <= {lookbackMs}] and (EventID=11707 or EventID=11724)]]";
        ProcessLog(context, "Setup", query, token, record =>
        {
            var description = TryFormatDescription(record);
            if (KeywordCatalog.ContainsCheatIndicator(description))
            {
                var timestamp = ResolveTimestamp(record, context.Options.ScanTimestampUtc);
                findings.Add(new ForensicFinding(
                    Severity.High,
                    ArtifactCategory.EventLogs,
                    "Setup log indicates potentially unauthorized software",
                    $"Setup Event ID {record.Id}",
                    timestamp,
                    description));
            }
        });
    }

    private static void AnalyzeTaskSchedulerLog(ScanContext context, ICollection<ForensicFinding> findings, long lookbackMs, CancellationToken token)
    {
        const string logName = "Microsoft-Windows-TaskScheduler/Operational";
        var query = $"*[System[TimeCreated[timediff(@SystemTime) <= {lookbackMs}] and (EventID=106 or EventID=140 or EventID=141)]]";
        ProcessLog(context, logName, query, token, record =>
        {
            var description = TryFormatDescription(record);
            if (KeywordCatalog.ContainsCheatIndicator(description) || KeywordCatalog.LogClearingCommands.Any(cmd => description.Contains(cmd, StringComparison.OrdinalIgnoreCase)))
            {
                var timestamp = ResolveTimestamp(record, context.Options.ScanTimestampUtc);
                findings.Add(new ForensicFinding(
                    Severity.High,
                    ArtifactCategory.EventLogs,
                    "Suspicious scheduled task activity",
                    $"{logName} Event ID {record.Id}",
                    timestamp,
                    description));
            }
        });
    }

    private static void AnalyzePowerShellLog(ScanContext context, ICollection<ForensicFinding> findings, long lookbackMs, CancellationToken token)
    {
        const string logName = "Microsoft-Windows-PowerShell/Operational";
        var query = $"*[System[TimeCreated[timediff(@SystemTime) <= {lookbackMs}] and (EventID=4103 or EventID=4104)]]";
        ProcessLog(context, logName, query, token, record =>
        {
            var script = ExtractScriptContent(record);
            if (string.IsNullOrWhiteSpace(script))
            {
                return;
            }

            var timestamp = ResolveTimestamp(record, context.Options.ScanTimestampUtc);
            if (KeywordCatalog.ContainsCheatIndicator(script) || KeywordCatalog.LogClearingCommands.Any(cmd => script.Contains(cmd, StringComparison.OrdinalIgnoreCase)))
            {
                findings.Add(new ForensicFinding(
                    Severity.High,
                    ArtifactCategory.EventLogs,
                    "PowerShell command history contains suspicious content",
                    $"{logName} Event ID {record.Id}",
                    timestamp,
                    script));
            }
            else
            {
                findings.Add(new ForensicFinding(
                    Severity.Medium,
                    ArtifactCategory.EventLogs,
                    "PowerShell command executed",
                    $"{logName} Event ID {record.Id}",
                    timestamp,
                    script));
            }
        });
    }

    private static void ProcessLog(ScanContext context, string logName, string query, CancellationToken token, Action<EventRecord> handler)
    {
        try
        {
            var eventQuery = new EventLogQuery(logName, PathType.LogName, query)
            {
                ReverseDirection = true
            };
            using var reader = new EventLogReader(eventQuery);
            int processed = 0;
            EventRecord? record;
            while (processed < MaxEventsPerLog && (record = reader.ReadEvent()) != null)
            {
                token.ThrowIfCancellationRequested();
                using (record)
                {
                    handler(record);
                }

                processed++;
            }
        }
        catch (EventLogNotFoundException)
        {
            context.Logger.Verbose($"Log {logName} not found; skipping.");
        }
        catch (EventLogException ex)
        {
            context.Logger.Warn($"Unable to read {logName} log: {ex.Message}");
        }
        catch (UnauthorizedAccessException ex)
        {
            context.Logger.Warn($"Access denied when reading {logName}: {ex.Message}");
        }
    }

    private static DateTimeOffset ResolveTimestamp(EventRecord record, DateTimeOffset fallback)
    {
        if (record.TimeCreated is DateTime created)
        {
            if (created.Kind == DateTimeKind.Unspecified)
            {
                created = DateTime.SpecifyKind(created, DateTimeKind.Local);
            }

            return new DateTimeOffset(created);
        }

        return fallback;
    }

    private static string TryFormatDescription(EventRecord record)
    {
        try
        {
            return record.FormatDescription() ?? string.Empty;
        }
        catch
        {
            var builder = new StringBuilder();
            builder.Append('[').Append(record.Id).Append("] ");
            foreach (var property in record.Properties)
            {
                builder.Append(property.Value).Append(';');
            }
            return builder.ToString();
        }
    }

    private static string ExtractScriptContent(EventRecord record)
    {
        try
        {
            if (record.Properties.Count > 0)
            {
                return string.Join(" | ", record.Properties.Select(p => p.Value?.ToString()).Where(value => !string.IsNullOrWhiteSpace(value)));
            }
        }
        catch
        {
            // ignored
        }
        return TryFormatDescription(record);
    }
}
