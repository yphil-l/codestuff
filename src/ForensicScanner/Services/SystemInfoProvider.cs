using ForensicScanner.Models;
using ForensicScanner.Utilities;
using Microsoft.Win32;
using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;

namespace ForensicScanner.Services;

public sealed class SystemInfoProvider
{
    public Task<SystemInformation> GetAsync(CancellationToken token)
    {
        return Task.Run(() => Collect(token), token);
    }

    private static SystemInformation Collect(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        string machine = Environment.MachineName;
        string user = Environment.UserName;
        string domain = Environment.UserDomainName;
        string osDescription = RuntimeInformation.OSDescription;
        bool is64Bit = Environment.Is64BitOperatingSystem;
        bool isAdmin = SecurityUtilities.IsRunningAsAdministrator();
        string? culture = CultureInfo.CurrentCulture?.DisplayName;
        string? timeZone = TimeZoneInfo.Local.DisplayName;
        string? processorArch = RuntimeInformation.ProcessArchitecture.ToString();
        string? windowsEdition = null;
        DateTimeOffset? lastBoot = null;
        TimeSpan? uptime = null;

        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT LastBootUpTime FROM Win32_OperatingSystem");
                foreach (var obj in searcher.Get())
                {
                    var raw = obj["LastBootUpTime"]?.ToString();
                    if (!string.IsNullOrWhiteSpace(raw))
                    {
                        lastBoot = ManagementDateTimeConverter.ToDateTime(raw);
                        uptime = DateTimeOffset.UtcNow - lastBoot.Value.ToUniversalTime();
                        break;
                    }
                }
            }
            catch
            {
                // ignore WMI failures
            }

            try
            {
                var view = Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32;
                using var key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view)
                    .OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
                windowsEdition = key?.GetValue("ProductName")?.ToString();
            }
            catch
            {
                // ignore registry failures
            }
        }

        return new SystemInformation(
            MachineName: machine,
            UserName: user,
            Domain: domain,
            OsDescription: osDescription,
            Is64BitOperatingSystem: is64Bit,
            IsAdministrator: isAdmin,
            LastBootTime: lastBoot,
            Uptime: uptime,
            WindowsEdition: windowsEdition,
            Culture: culture,
            TimeZoneDisplay: timeZone,
            ProcessorArchitecture: processorArch);
    }
}
