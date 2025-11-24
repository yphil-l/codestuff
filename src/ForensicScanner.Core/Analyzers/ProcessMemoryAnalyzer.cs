using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using ForensicScanner.Core.Models;

namespace ForensicScanner.Core.Analyzers;

public class ProcessMemoryAnalyzer : IAnalyzer
{
    public string Name => "Process Memory Scanner";
    public ScanDepth RequiredDepth => ScanDepth.Deep;

    private static readonly string[] TargetProcesses = { "javaw", "explorer", "csrss" };
    private static readonly string[] SuspiciousKeywords =
    {
        "cheat", "inject", "hack", "dll", "bypass", "spoof"
    };

    [Flags]
    private enum ProcessAccessFlags : uint
    {
        QueryInformation = 0x0400,
        VMRead = 0x0010
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(ProcessAccessFlags access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hHandle);

    public Task<List<Finding>> AnalyzeAsync(ScanContext context)
    {
        var findings = new List<Finding>();

        foreach (var processName in TargetProcesses)
        {
            var processes = Process.GetProcessesByName(processName);
            foreach (var process in processes)
            {
                try
                {
                    var handle = OpenProcess(ProcessAccessFlags.QueryInformation | ProcessAccessFlags.VMRead, false, process.Id);
                    if (handle == IntPtr.Zero)
                    {
                        findings.Add(new Finding
                        {
                            Severity = SeverityLevel.Normal,
                            Title = $"Unable to open process {processName}",
                            Explanation = "Failed to obtain handle for process memory scanning.",
                            ArtifactPath = process.ProcessName,
                            Category = "Process Memory"
                        });
                        continue;
                    }

                    var scanResult = ScanProcessMemory(process, handle);
                    findings.AddRange(scanResult);

                    CloseHandle(handle);
                }
                catch (Exception ex)
                {
                    findings.Add(new Finding
                    {
                        Severity = SeverityLevel.Normal,
                        Title = $"Process Scan Error - {processName}",
                        Explanation = $"Error scanning process memory: {ex.Message}",
                        ArtifactPath = process.ProcessName,
                        Category = "Process Memory"
                    });
                }
                finally
                {
                    process.Dispose();
                }
            }
        }

        return Task.FromResult(findings);
    }

    private List<Finding> ScanProcessMemory(Process process, IntPtr handle)
    {
        var findings = new List<Finding>();

        try
        {
            var baseAddress = process.MainModule?.BaseAddress ?? IntPtr.Zero;
            var moduleSize = process.MainModule?.ModuleMemorySize ?? 0;

            if (baseAddress == IntPtr.Zero || moduleSize == 0)
                return findings;

            var bufferSize = Math.Min(moduleSize, 1024 * 1024);
            var buffer = new byte[bufferSize];

            if (ReadProcessMemory(handle, baseAddress, buffer, buffer.Length, out var bytesRead) && bytesRead.ToInt32() > 0)
            {
                var text = Encoding.ASCII.GetString(buffer);
                foreach (var keyword in SuspiciousKeywords)
                {
                    if (text.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        findings.Add(new Finding
                        {
                            Severity = SeverityLevel.Cheat,
                            Title = $"Suspicious string '{keyword}' detected in {process.ProcessName}",
                            Explanation = $"Process memory contains suspicious keyword '{keyword}'.",
                            ArtifactPath = process.ProcessName,
                            Category = "Process Memory"
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            findings.Add(new Finding
            {
                Severity = SeverityLevel.Normal,
                Title = $"Process Memory Scan Failed - {process.ProcessName}",
                Explanation = $"Failed to read process memory: {ex.Message}",
                ArtifactPath = process.ProcessName,
                Category = "Process Memory"
            });
        }

        return findings;
    }
}
