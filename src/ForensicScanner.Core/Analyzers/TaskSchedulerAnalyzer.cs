using System.Xml.Linq;
using ForensicScanner.Core.Models;

namespace ForensicScanner.Core.Analyzers;

public class TaskSchedulerAnalyzer : IAnalyzer
{
    public string Name => "Task Scheduler Parser";
    public ScanDepth RequiredDepth => ScanDepth.Medium;

    private static readonly string TasksDirectory = @"C:\Windows\System32\Tasks";

    public Task<List<Finding>> AnalyzeAsync(ScanContext context)
    {
        var findings = new List<Finding>();

        if (!Directory.Exists(TasksDirectory))
        {
            findings.Add(new Finding
            {
                Severity = SeverityLevel.Normal,
                Title = "Task Scheduler Directory Missing",
                Explanation = "Task Scheduler directory not found. Unable to analyze scheduled tasks.",
                ArtifactPath = TasksDirectory,
                Category = "Task Scheduler"
            });
            return Task.FromResult(findings);
        }

        foreach (var taskFile in Directory.EnumerateFiles(TasksDirectory, "*", SearchOption.AllDirectories))
        {
            try
            {
                AnalyzeTaskFile(taskFile, findings);
            }
            catch (Exception ex)
            {
                findings.Add(new Finding
                {
                    Severity = SeverityLevel.Normal,
                    Title = "Task File Read Error",
                    Explanation = $"Error reading task file {taskFile}: {ex.Message}",
                    ArtifactPath = taskFile,
                    Category = "Task Scheduler"
                });
            }
        }

        return Task.FromResult(findings);
    }

    private void AnalyzeTaskFile(string taskFile, List<Finding> findings)
    {
        var xml = XDocument.Load(taskFile);
        var taskName = Path.GetFileName(taskFile);
        var execNode = xml.Descendants().FirstOrDefault(x => x.Name.LocalName == "Command");
        var argumentsNode = xml.Descendants().FirstOrDefault(x => x.Name.LocalName == "Arguments");
        var triggerNode = xml.Descendants().FirstOrDefault(x => x.Name.LocalName == "Triggers");

        var command = execNode?.Value ?? "N/A";
        var arguments = argumentsNode?.Value ?? string.Empty;
        var trigger = triggerNode?.Value ?? "Unknown";

        var severity = AssessTaskSeverity(command, arguments, trigger);

        findings.Add(new Finding
        {
            Severity = severity,
            Title = $"Scheduled Task: {taskName}",
            Explanation = $"Command: {command} {arguments}. Trigger: {trigger}",
            ArtifactPath = taskFile,
            Category = "Task Scheduler",
            Timestamp = File.GetLastWriteTime(taskFile)
        });
    }

    private SeverityLevel AssessTaskSeverity(string command, string arguments, string trigger)
    {
        var lowerCommand = command.ToLowerInvariant();
        var lowerArgs = arguments.ToLowerInvariant();

        if (lowerCommand.Contains("powershell") && lowerArgs.Contains("hidden"))
            return SeverityLevel.Cheat;
        if (lowerCommand.Contains("cmd.exe") && lowerArgs.Contains("/c"))
            return SeverityLevel.VerySus;
        if (lowerCommand.Contains("temp") || lowerCommand.Contains("appdata"))
            return SeverityLevel.VerySus;
        if (trigger.Contains("Boot", StringComparison.OrdinalIgnoreCase) || trigger.Contains("Logon", StringComparison.OrdinalIgnoreCase))
            return SeverityLevel.SlightlySus;

        return SeverityLevel.Normal;
    }
}
