using System.Diagnostics.Eventing.Reader;
using ForensicScanner.Core.Models;

namespace ForensicScanner.Core.Analyzers;

public class EventLogAnalyzer : IAnalyzer
{
    public string Name => "Event Log Analyzer";
    public ScanDepth RequiredDepth => ScanDepth.Light;

    private static readonly Dictionary<int, string> SuspiciousEventIds = new()
    {
        { 1102, "Security audit log was cleared" },
        { 104, "Log file was cleared" },
        { 4616, "System time was changed" },
        { 3079, "USN journal was deleted" },
        { 7034, "Service crashed unexpectedly" },
        { 7036, "Service state changed" },
        { 7040, "Service start type changed" }
    };

    public async Task<List<Finding>> AnalyzeAsync(ScanContext context)
    {
        var findings = new List<Finding>();

        await Task.Run(() =>
        {
            try
            {
                CheckSecurityLog(findings);
                CheckSystemLog(findings);
                CheckApplicationLog(findings);
            }
            catch (Exception ex)
            {
                findings.Add(new Finding
                {
                    Severity = SeverityLevel.Normal,
                    Title = "Event Log Access Issue",
                    Explanation = $"Unable to read event logs. {ex.Message}",
                    ArtifactPath = "Event Viewer",
                    Category = "Event Logs"
                });
            }
        }, context.CancellationToken);

        return findings;
    }

    private void CheckSecurityLog(List<Finding> findings)
    {
        try
        {
            CheckEventLog("Security", findings, new[] { 1102, 4616, 4719 });
        }
        catch (UnauthorizedAccessException)
        {
            findings.Add(new Finding
            {
                Severity = SeverityLevel.Normal,
                Title = "Security Log Access Denied",
                Explanation = "Security log requires elevated privileges. Run as Administrator.",
                ArtifactPath = "Security Event Log",
                Category = "Event Logs"
            });
        }
        catch (Exception ex)
        {
            findings.Add(new Finding
            {
                Severity = SeverityLevel.Normal,
                Title = "Security Log Read Error",
                Explanation = $"Error reading Security log: {ex.Message}",
                ArtifactPath = "Security Event Log",
                Category = "Event Logs"
            });
        }
    }

    private void CheckSystemLog(List<Finding> findings)
    {
        try
        {
            CheckEventLog("System", findings, new[] { 104, 3079, 7034, 7036, 7040 });
        }
        catch (Exception ex)
        {
            findings.Add(new Finding
            {
                Severity = SeverityLevel.Normal,
                Title = "System Log Read Error",
                Explanation = $"Error reading System log: {ex.Message}",
                ArtifactPath = "System Event Log",
                Category = "Event Logs"
            });
        }
    }

    private void CheckApplicationLog(List<Finding> findings)
    {
        try
        {
            CheckEventLog("Application", findings, new[] { 1000, 1001, 1002 });
        }
        catch (Exception ex)
        {
            findings.Add(new Finding
            {
                Severity = SeverityLevel.Normal,
                Title = "Application Log Read Error",
                Explanation = $"Error reading Application log: {ex.Message}",
                ArtifactPath = "Application Event Log",
                Category = "Event Logs"
            });
        }
    }

    private void CheckEventLog(string logName, List<Finding> findings, int[] targetEventIds)
    {
        var query = new EventLogQuery(logName, PathType.LogName);
        using var reader = new EventLogReader(query);
        
        var recentEvents = new List<EventRecord>();
        var now = DateTime.Now;
        var sevenDaysAgo = now.AddDays(-7);

        EventRecord? eventRecord;
        while ((eventRecord = reader.ReadEvent()) != null)
        {
            using (eventRecord)
            {
                if (eventRecord.TimeCreated.HasValue && 
                    eventRecord.TimeCreated.Value >= sevenDaysAgo &&
                    targetEventIds.Contains(eventRecord.Id))
                {
                    recentEvents.Add(eventRecord);
                    
                    if (recentEvents.Count >= 100)
                        break;
                }
            }
        }

        foreach (var evt in recentEvents.Take(50))
        {
            AnalyzeEvent(evt, findings, logName);
        }
    }

    private void AnalyzeEvent(EventRecord evt, List<Finding> findings, string logName)
    {
        var eventId = evt.Id;
        var severity = DetermineSeverity(eventId);
        var description = SuspiciousEventIds.GetValueOrDefault(eventId, "Suspicious event");

        findings.Add(new Finding
        {
            Severity = severity,
            Title = $"Event ID {eventId} detected in {logName}",
            Explanation = $"{description}. This may indicate tampering or evasion attempts.",
            ArtifactPath = $"Event Viewer > {logName} > Event ID {eventId} at {evt.TimeCreated:yyyy-MM-dd HH:mm:ss}",
            Category = "Event Logs",
            Timestamp = evt.TimeCreated ?? DateTime.Now
        });
    }

    private SeverityLevel DetermineSeverity(int eventId)
    {
        return eventId switch
        {
            1102 => SeverityLevel.VerySus,
            104 => SeverityLevel.VerySus,
            4616 => SeverityLevel.SlightlySus,
            3079 => SeverityLevel.Cheat,
            7034 or 7036 or 7040 => SeverityLevel.Normal,
            _ => SeverityLevel.SlightlySus
        };
    }
}
