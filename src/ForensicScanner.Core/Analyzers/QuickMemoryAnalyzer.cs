using System.Diagnostics;
using ForensicScanner.Core.Models;

namespace ForensicScanner.Core.Analyzers;

public class QuickMemoryAnalyzer : IAnalyzer
{
    public string Name => "Quick Memory Scan";
    public ScanDepth RequiredDepth => ScanDepth.Light;

    private static readonly string[] TargetProcesses = { "javaw", "explorer", "csrss" };

    public Task<List<Finding>> AnalyzeAsync(ScanContext context)
    {
        var findings = new List<Finding>();

        foreach (var target in TargetProcesses)
        {
            var processes = Process.GetProcessesByName(target);
            if (processes.Length == 0)
            {
                findings.Add(new Finding
                {
                    Severity = SeverityLevel.SlightlySus,
                    Title = $"Process {target}.exe not running",
                    Explanation = $"Expected process {target}.exe is not running. This could suggest tampering or termination.",
                    ArtifactPath = target,
                    Category = "Memory"
                });
                continue;
            }

            foreach (var proc in processes)
            {
                try
                {
                    var modules = proc.Modules;
                    foreach (ProcessModule module in modules)
                    {
                        if (module.FileName.Contains("temp", StringComparison.OrdinalIgnoreCase) ||
                            module.FileName.Contains("AppData", StringComparison.OrdinalIgnoreCase))
                        {
                            findings.Add(new Finding
                            {
                                Severity = SeverityLevel.VerySus,
                                Title = $"Suspicious module injected in {proc.ProcessName}",
                                Explanation = $"Module {module.ModuleName} loaded from {module.FileName}",
                                ArtifactPath = module.FileName,
                                Category = "Memory",
                                Timestamp = DateTime.Now
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    findings.Add(new Finding
                    {
                        Severity = SeverityLevel.Normal,
                        Title = $"Memory inspection failed for {proc.ProcessName}",
                        Explanation = $"Unable to inspect process modules: {ex.Message}",
                        ArtifactPath = proc.ProcessName,
                        Category = "Memory"
                    });
                }
                finally
                {
                    proc.Dispose();
                }
            }
        }

        return Task.FromResult(findings);
    }
}
