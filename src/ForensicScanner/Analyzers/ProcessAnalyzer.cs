using ForensicScanner.Logging;
using ForensicScanner.Models;
using ForensicScanner.Services;
using ForensicScanner.Utilities;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace ForensicScanner.Analyzers;

public sealed class ProcessAnalyzer : IArtifactAnalyzer
{
    private static readonly HashSet<string> CoreProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer",
        "javaw",
        "csrss",
        "svchost"
    };

    public ArtifactCategory Category => ArtifactCategory.Processes;

    public Task<IReadOnlyCollection<ForensicFinding>> AnalyzeAsync(ScanContext context, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            context.Logger.Warn("Process analysis is only available on Windows hosts.");
            return Task.FromResult<IReadOnlyCollection<ForensicFinding>>(Array.Empty<ForensicFinding>());
        }

        var findings = new List<ForensicFinding>();
        var processes = Process.GetProcesses();
        var commandLines = BuildCommandLineMap(context.Logger);
        var connections = CaptureNetworkConnections(context.Logger);

        foreach (var process in processes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using (process)
            {
                ProcessSnapshot? snapshot = CaptureSnapshot(process, commandLines, connections, context.Logger);
                if (snapshot is null)
                {
                    continue;
                }

                EvaluateProcess(snapshot, context, findings);
            }
        }

        return Task.FromResult<IReadOnlyCollection<ForensicFinding>>(new ReadOnlyCollection<ForensicFinding>(findings));
    }

    private static Dictionary<int, string> BuildCommandLineMap(ILogger logger)
    {
        var map = new Dictionary<int, string>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT ProcessId, CommandLine FROM Win32_Process");
            foreach (ManagementObject obj in searcher.Get())
            {
                if (obj["ProcessId"] is not uint pid)
                {
                    continue;
                }

                var commandLine = obj["CommandLine"]?.ToString() ?? string.Empty;
                map[(int)pid] = commandLine;
            }
        }
        catch (Exception ex)
        {
            logger.Verbose($"Unable to query process command lines: {ex.Message}");
        }

        return map;
    }

    private static Dictionary<int, List<ProcessConnection>> CaptureNetworkConnections(ILogger logger)
    {
        var result = new Dictionary<int, List<ProcessConnection>>();
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "netstat",
                Arguments = "-ano",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return result;
            }

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(3000);

            foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = line.Trim();
                if (!trimmed.StartsWith("TCP", StringComparison.OrdinalIgnoreCase) && !trimmed.StartsWith("UDP", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var columns = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (columns.Length < 4)
                {
                    continue;
                }

                var protocol = columns[0].ToUpperInvariant();
                string local = columns[1];
                string remote;
                string state;
                int pidIndex;

                if (protocol == "TCP")
                {
                    if (columns.Length < 5)
                    {
                        continue;
                    }

                    remote = columns[2];
                    state = columns[3];
                    pidIndex = 4;
                }
                else
                {
                    remote = columns[2];
                    state = "UDP";
                    pidIndex = 3;
                }

                if (!int.TryParse(columns[pidIndex], out var pid))
                {
                    continue;
                }

                var connection = new ProcessConnection(protocol, local, remote, state);
                if (!result.TryGetValue(pid, out var list))
                {
                    list = new List<ProcessConnection>();
                    result[pid] = list;
                }
                list.Add(connection);
            }
        }
        catch (Exception ex)
        {
            logger.Verbose($"Failed to capture network connections: {ex.Message}");
        }

        return result;
    }

    private static ProcessSnapshot? CaptureSnapshot(Process process, IReadOnlyDictionary<int, string> commandLines, IReadOnlyDictionary<int, List<ProcessConnection>> connections, ILogger logger)
    {
        try
        {
            string? imagePath = null;
            try
            {
                imagePath = process.MainModule?.FileName;
            }
            catch (Exception ex)
            {
                logger.Verbose($"Unable to read main module for PID {process.Id}: {ex.Message}");
            }

            var modules = new List<ModuleSnapshot>();
            try
            {
                foreach (ProcessModule module in process.Modules)
                {
                    modules.Add(new ModuleSnapshot(module.FileName ?? module.ModuleName, module.BaseAddress, module.ModuleMemorySize));
                }
            }
            catch (Exception ex)
            {
                logger.Verbose($"Module enumeration failed for PID {process.Id}: {ex.Message}");
            }

            var commandLine = commandLines.TryGetValue(process.Id, out var cmd) ? cmd : string.Empty;
            var connectionList = connections.TryGetValue(process.Id, out var conn) ? conn : Array.Empty<ProcessConnection>();

            DateTimeOffset? startTime = null;
            try
            {
                startTime = new DateTimeOffset(process.StartTime);
            }
            catch
            {
                // ignored
            }

            return new ProcessSnapshot(
                process.ProcessName,
                process.Id,
                imagePath,
                commandLine,
                modules,
                connectionList,
                startTime);
        }
        catch
        {
            return null;
        }
    }

    private static void EvaluateProcess(ProcessSnapshot snapshot, ScanContext context, ICollection<ForensicFinding> findings)
    {
        var reasons = new List<(Severity Severity, string Description, string Context)>();

        if (KeywordCatalog.ContainsCheatIndicator(snapshot.ProcessName) || KeywordCatalog.ContainsCheatIndicator(snapshot.CommandLine) || KeywordCatalog.ContainsCheatIndicator(snapshot.ImagePath))
        {
            reasons.Add((Severity.High, "Process metadata indicates cheat artifact", BuildContext(snapshot)));
        }

        if (PathUtilities.IsUserWritablePath(snapshot.ImagePath))
        {
            reasons.Add((Severity.High, "Process executing from user-writable directory", snapshot.ImagePath ?? string.Empty));
        }

        if (snapshot.ProcessName.Equals("svchost", StringComparison.OrdinalIgnoreCase) && !PathUtilities.IsSystemPath(snapshot.ImagePath))
        {
            reasons.Add((Severity.Critical, "svchost.exe running outside system directory (possible hollowing)", snapshot.ImagePath ?? string.Empty));
        }

        var injectedModule = snapshot.Modules.FirstOrDefault(module => KeywordCatalog.ContainsCheatIndicator(module.Path));
        if (injectedModule is not null)
        {
            reasons.Add((Severity.High, "Injected module name matches cheat indicator", injectedModule.Path ?? string.Empty));
        }

        var nonSystemModules = snapshot.Modules.Where(module => PathUtilities.IsUserWritablePath(module.Path)).Take(3).ToList();
        if (nonSystemModules.Count > 0)
        {
            reasons.Add((Severity.Medium, "Modules loaded from user-writable locations", string.Join(" | ", nonSystemModules.Select(m => m.Path))));
        }

        var suspiciousConnections = snapshot.Connections.Where(IsExternalConnection).ToList();
        if (suspiciousConnections.Count > 0)
        {
            var severity = suspiciousConnections.Count >= 3 ? Severity.High : Severity.Medium;
            reasons.Add((severity, "Process maintains external network connections", string.Join(" | ", suspiciousConnections.Select(c => c.ToString()))));
        }

        if (context.Options.DeepMemoryAnalysis)
        {
            foreach (var hit in MemoryScanner.Scan(snapshot, context.Logger))
            {
                reasons.Add((Severity.High, "Suspicious string recovered from process memory", hit));
            }
        }

        if (reasons.Count == 0)
        {
            if (CoreProcesses.Contains(snapshot.ProcessName))
            {
                findings.Add(new ForensicFinding(
                    Severity.Low,
                    ArtifactCategory.Processes,
                    "Core Windows process observed",
                    snapshot.ImagePath ?? snapshot.ProcessName,
                    snapshot.StartTime,
                    BuildContext(snapshot)));
            }
            return;
        }

        foreach (var reason in reasons)
        {
            findings.Add(new ForensicFinding(
                reason.Severity,
                ArtifactCategory.Processes,
                reason.Description,
                snapshot.ImagePath ?? snapshot.ProcessName,
                snapshot.StartTime,
                reason.Context));
        }
    }

    private static string BuildContext(ProcessSnapshot snapshot)
    {
        var builder = new StringBuilder();
        builder.Append("PID=").Append(snapshot.ProcessId);
        if (!string.IsNullOrWhiteSpace(snapshot.CommandLine))
        {
            builder.Append(" | Cmd=").Append(snapshot.CommandLine);
        }

        if (snapshot.Connections.Any())
        {
            builder.Append(" | Connections=").Append(string.Join(",", snapshot.Connections.Take(3)));
        }

        var moduleNames = snapshot.Modules
            .Select(m => m.Path)
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => Path.GetFileName(p!) ?? p!)
            .Take(5)
            .ToList();
        if (moduleNames.Count > 0)
        {
            builder.Append(" | Modules=").Append(string.Join(",", moduleNames));
        }

        return builder.ToString();
    }

    private static bool IsExternalConnection(ProcessConnection connection)
    {
        var remoteHost = ExtractHost(connection.RemoteAddress);
        if (string.IsNullOrWhiteSpace(remoteHost) || remoteHost == "0.0.0.0" || remoteHost.Contains('*') || remoteHost.StartsWith("[::", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (remoteHost.Contains(":"))
        {
            remoteHost = remoteHost.Split(':')[0];
        }

        if (!IPAddress.TryParse(remoteHost, out var address))
        {
            return false;
        }

        if (IPAddress.IsLoopback(address))
        {
            return false;
        }

        var bytes = address.GetAddressBytes();
        // Private ranges
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            if (bytes[0] == 10)
            {
                return false;
            }
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            {
                return false;
            }
            if (bytes[0] == 192 && bytes[1] == 168)
            {
                return false;
            }
        }

        return true;
    }

    private static string ExtractHost(string endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            return string.Empty;
        }

        endpoint = endpoint.Trim();
        if (endpoint.StartsWith("[", StringComparison.Ordinal))
        {
            var closing = endpoint.IndexOf(']');
            if (closing > 0)
            {
                return endpoint.Substring(1, closing - 1);
            }
        }

        var separatorIndex = endpoint.LastIndexOf(':');
        if (separatorIndex > 0)
        {
            return endpoint.Substring(0, separatorIndex);
        }

        return endpoint;
    }

    private sealed record ProcessSnapshot(
        string ProcessName,
        int ProcessId,
        string? ImagePath,
        string CommandLine,
        IReadOnlyList<ModuleSnapshot> Modules,
        IReadOnlyList<ProcessConnection> Connections,
        DateTimeOffset? StartTime);

    private sealed record ModuleSnapshot(string? Path, IntPtr BaseAddress, int Size);

    private sealed record ProcessConnection(string Protocol, string LocalAddress, string RemoteAddress, string State)
    {
        public override string ToString() => $"{Protocol} {LocalAddress} -> {RemoteAddress} ({State})";
    }

    private static class MemoryScanner
    {
        private const int MaxBytesPerModule = 64 * 1024;

        public static IEnumerable<string> Scan(ProcessSnapshot snapshot, ILogger logger)
        {
            IntPtr handle = IntPtr.Zero;
            try
            {
                handle = NativeMethods.OpenProcess(NativeMethods.ProcessAccessFlags.VirtualMemoryRead | NativeMethods.ProcessAccessFlags.QueryInformation, false, snapshot.ProcessId);
                if (handle == IntPtr.Zero)
                {
                    yield break;
                }

                foreach (var module in snapshot.Modules.Take(10))
                {
                    if (module.BaseAddress == IntPtr.Zero || module.Size <= 0)
                    {
                        continue;
                    }

                    int length = Math.Min(module.Size, MaxBytesPerModule);
                    var buffer = new byte[length];
                    if (!NativeMethods.ReadProcessMemory(handle, module.BaseAddress, buffer, length, out var bytesRead) || bytesRead == 0)
                    {
                        continue;
                    }

                    var text = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                    foreach (var keyword in KeywordCatalog.CheatIndicators)
                    {
                        if (text.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            yield return $"Keyword '{keyword}' within module {module.Path}";
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                logger.Verbose($"Memory scan failed for PID {snapshot.ProcessId}: {ex.Message}");
            }
            finally
            {
                if (handle != IntPtr.Zero)
                {
                    NativeMethods.CloseHandle(handle);
                }
            }
        }
    }

    private static class NativeMethods
    {
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            QueryInformation = 0x0400,
            VirtualMemoryRead = 0x0010
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags access, bool inheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
    }
}
