using ForensicScanner.Logging;
using ForensicScanner.Models;
using ForensicScanner.Services;
using ForensicScanner.Utilities;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.Linq;

namespace ForensicScanner.Analyzers;

public sealed class RegistryAnalyzer : IArtifactAnalyzer
{
    public ArtifactCategory Category => ArtifactCategory.Registry;

    public Task<IReadOnlyCollection<ForensicFinding>> AnalyzeAsync(ScanContext context, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            context.Logger.Warn("Registry analysis is only available on Windows hosts.");
            return Task.FromResult<IReadOnlyCollection<ForensicFinding>>(Array.Empty<ForensicFinding>());
        }

        var findings = new List<ForensicFinding>();

        InspectDefenderAndFirewallPolicies(context, findings);
        InspectSecurityPolicies(context, findings);
        InspectServices(context, findings, cancellationToken);
        InspectRunKeys(context, findings, RegistryHive.LocalMachine, cancellationToken);
        InspectRunKeys(context, findings, RegistryHive.CurrentUser, cancellationToken);
        InspectUserAssist(context, findings, cancellationToken);
        InspectRunMru(context, findings, cancellationToken);
        InspectUninstallEvidence(context, findings, cancellationToken);
        InspectNetworkSettings(context, findings);

        return Task.FromResult<IReadOnlyCollection<ForensicFinding>>(new ReadOnlyCollection<ForensicFinding>(findings));
    }

    private static void InspectDefenderAndFirewallPolicies(ScanContext context, ICollection<ForensicFinding> findings)
    {
        var securityKeys = new[]
        {
            (Hive: RegistryHive.LocalMachine, Path: @"SOFTWARE\\Policies\\Microsoft\\Windows Defender", ValueNames: new[] { "DisableAntiSpyware", "DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableOnAccessProtection", "DisableIOAVProtection" }),
            (Hive: RegistryHive.LocalMachine, Path: @"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", ValueNames: new[] { "DisableRealtimeMonitoring", "DisableBehaviorMonitoring" }),
            (Hive: RegistryHive.LocalMachine, Path: @"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile", ValueNames: new[] { "EnableFirewall" }),
            (Hive: RegistryHive.LocalMachine, Path: @"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile", ValueNames: new[] { "EnableFirewall" })
        };

        foreach (var keyInfo in securityKeys)
        {
            using var key = OpenKey(keyInfo.Hive, context.RegistryView, keyInfo.Path);
            if (key is null)
            {
                continue;
            }

            foreach (var valueName in keyInfo.ValueNames)
            {
                var value = key.GetValue(valueName);
                if (value is int intValue)
                {
                    if (valueName.StartsWith("Enable", StringComparison.OrdinalIgnoreCase) && intValue == 0)
                    {
                        findings.Add(new ForensicFinding(
                            Severity.High,
                            Category,
                            $"Windows Firewall profile disabled ({valueName})",
                            $"HKLM:{keyInfo.Path}",
                            context.Options.ScanTimestampUtc,
                            $"Value {valueName}={intValue}"));
                    }
                    else if (valueName.StartsWith("Disable", StringComparison.OrdinalIgnoreCase) && intValue == 1)
                    {
                        findings.Add(new ForensicFinding(
                            Severity.Critical,
                            Category,
                            $"Security feature disabled ({valueName})",
                            $"HKLM:{keyInfo.Path}",
                            context.Options.ScanTimestampUtc,
                            $"Value {valueName}={intValue}"));
                    }
                }
            }
        }
    }

    private static void InspectSecurityPolicies(ScanContext context, ICollection<ForensicFinding> findings)
    {
        const string policyPath = @"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
        using var key = OpenKey(RegistryHive.LocalMachine, context.RegistryView, policyPath);
        if (key is null)
        {
            return;
        }

        var enableLua = key.GetValue("EnableLUA") as int?;
        if (enableLua.HasValue && enableLua.Value == 0)
        {
            findings.Add(new ForensicFinding(
                Severity.High,
                Category,
                "User Account Control (UAC) disabled",
                $"HKLM:{policyPath}",
                context.Options.ScanTimestampUtc,
                "EnableLUA=0"));
        }

        var consent = key.GetValue("ConsentPromptBehaviorAdmin") as int?;
        if (consent.HasValue && consent.Value == 0)
        {
            findings.Add(new ForensicFinding(
                Severity.Medium,
                Category,
                "Admin consent prompts suppressed",
                $"HKLM:{policyPath}",
                context.Options.ScanTimestampUtc,
                "ConsentPromptBehaviorAdmin=0"));
        }
    }

    private static void InspectServices(ScanContext context, ICollection<ForensicFinding> findings, CancellationToken token)
    {
        const string servicesPath = @"SYSTEM\\CurrentControlSet\\Services";
        using var servicesRoot = OpenKey(RegistryHive.LocalMachine, context.RegistryView, servicesPath);
        if (servicesRoot is null)
        {
            return;
        }

        var criticalServices = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "WinDefend",
            "Sense",
            "WdNisSvc",
            "wscsvc",
            "SecurityHealthService",
            "MBAMService"
        };

        foreach (var serviceName in servicesRoot.GetSubKeyNames())
        {
            token.ThrowIfCancellationRequested();

            if (!criticalServices.Contains(serviceName))
            {
                continue;
            }

            using var serviceKey = servicesRoot.OpenSubKey(serviceName);
            if (serviceKey is null)
            {
                continue;
            }

            var startValue = serviceKey.GetValue("Start") as int?;
            if (startValue.HasValue && startValue.Value == 4)
            {
                findings.Add(new ForensicFinding(
                    Severity.Critical,
                    Category,
                    $"Security service disabled ({serviceName})",
                    $"HKLM:{servicesPath}\\{serviceName}",
                    context.Options.ScanTimestampUtc,
                    "Start=4 (Disabled)"));
            }

            var imagePath = serviceKey.GetValue("ImagePath")?.ToString();
            if (!string.IsNullOrWhiteSpace(imagePath) && KeywordCatalog.ContainsSuspiciousDirectory(imagePath))
            {
                findings.Add(new ForensicFinding(
                    Severity.High,
                    Category,
                    $"Security service redirected to suspicious path ({serviceName})",
                    $"HKLM:{servicesPath}\\{serviceName}",
                    context.Options.ScanTimestampUtc,
                    imagePath));
            }
        }
    }

    private static void InspectRunKeys(ScanContext context, ICollection<ForensicFinding> findings, RegistryHive hive, CancellationToken token)
    {
        var runKeyPaths = new[]
        {
            @"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            @"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            @"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
            @"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
        };

        foreach (var path in runKeyPaths)
        {
            using var key = OpenKey(hive, context.RegistryView, path);
            if (key is null)
            {
                continue;
            }

            foreach (var valueName in key.GetValueNames())
            {
                token.ThrowIfCancellationRequested();

                RegistryValueKind kind;
                try
                {
                    kind = key.GetValueKind(valueName);
                }
                catch
                {
                    continue;
                }

                var value = key.GetValue(valueName)?.ToString();
                if (kind != RegistryValueKind.String && kind != RegistryValueKind.ExpandString)
                {
                    findings.Add(new ForensicFinding(
                        Severity.Medium,
                        Category,
                        "Unusual registry value type in persistence key",
                        $"{hive}:{path} -> {valueName}",
                        context.Options.ScanTimestampUtc,
                        $"Value type: {kind}"));
                }

                if (string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                if (KeywordCatalog.ContainsCheatIndicator(value) || KeywordCatalog.ContainsSuspiciousDirectory(value))
                {
                    findings.Add(new ForensicFinding(
                        Severity.High,
                        Category,
                        "Suspicious autorun entry detected",
                        $"{hive}:{path} -> {valueName}",
                        context.Options.ScanTimestampUtc,
                        value));
                }
            }
        }
    }

    private static void InspectUserAssist(ScanContext context, ICollection<ForensicFinding> findings, CancellationToken token)
    {
        foreach (var sid in ResolveUserSids(context))
        {
            token.ThrowIfCancellationRequested();
            string basePath = $"{sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
            using var userAssistRoot = OpenKey(RegistryHive.Users, context.RegistryView, basePath);
            if (userAssistRoot is null)
            {
                continue;
            }

            foreach (var guidKey in userAssistRoot.GetSubKeyNames())
            {
                using var countKey = userAssistRoot.OpenSubKey($"{guidKey}\\Count");
                if (countKey is null)
                {
                    continue;
                }

                foreach (var valueName in countKey.GetValueNames())
                {
                    var decoded = SecurityUtilities.Rot13(valueName);
                    if (KeywordCatalog.ContainsCheatIndicator(decoded))
                    {
                        findings.Add(new ForensicFinding(
                            Severity.Medium,
                            Category,
                            "Suspicious program execution history (UserAssist)",
                            $"HKU:{basePath}\\{guidKey}",
                            context.Options.ScanTimestampUtc,
                            decoded));
                    }
                }
            }
        }
    }

    private static void InspectRunMru(ScanContext context, ICollection<ForensicFinding> findings, CancellationToken token)
    {
        foreach (var sid in ResolveUserSids(context))
        {
            token.ThrowIfCancellationRequested();
            string path = $"{sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU";
            using var runMru = OpenKey(RegistryHive.Users, context.RegistryView, path);
            if (runMru is null)
            {
                continue;
            }

            foreach (var valueName in runMru.GetValueNames())
            {
                var command = runMru.GetValue(valueName)?.ToString();
                if (KeywordCatalog.ContainsCheatIndicator(command) || KeywordCatalog.ContainsSuspiciousDirectory(command))
                {
                    findings.Add(new ForensicFinding(
                        Severity.High,
                        Category,
                        "Suspicious entry in RunMRU",
                        $"HKU:{path} -> {valueName}",
                        context.Options.ScanTimestampUtc,
                        command));
                }
            }
        }
    }

    private static void InspectUninstallEvidence(ScanContext context, ICollection<ForensicFinding> findings, CancellationToken token)
    {
        var uninstallRoots = new[]
        {
            (RegistryHive.LocalMachine, @"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            (RegistryHive.LocalMachine, @"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            (RegistryHive.CurrentUser, @"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
        };

        foreach (var (hive, path) in uninstallRoots)
        {
            using var uninstallKey = OpenKey(hive, context.RegistryView, path);
            if (uninstallKey is null)
            {
                continue;
            }

            foreach (var subKeyName in uninstallKey.GetSubKeyNames())
            {
                token.ThrowIfCancellationRequested();
                using var appKey = uninstallKey.OpenSubKey(subKeyName);
                if (appKey is null)
                {
                    continue;
                }

                var displayName = appKey.GetValue("DisplayName")?.ToString();
                if (KeywordCatalog.ContainsCheatIndicator(displayName))
                {
                    findings.Add(new ForensicFinding(
                        Severity.Medium,
                        Category,
                        "Uninstall evidence references cheat-related software",
                        $"{hive}:{path}\\{subKeyName}",
                        context.Options.ScanTimestampUtc,
                        displayName));
                }
            }
        }
    }

    private static void InspectNetworkSettings(ScanContext context, ICollection<ForensicFinding> findings)
    {
        const string internetSettingsPath = @"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
        using var key = OpenKey(RegistryHive.CurrentUser, context.RegistryView, internetSettingsPath);
        if (key is null)
        {
            return;
        }

        var proxyEnabled = key.GetValue("ProxyEnable") as int?;
        if (proxyEnabled == 1)
        {
            var proxyServer = key.GetValue("ProxyServer")?.ToString();
            if (!string.IsNullOrWhiteSpace(proxyServer) && !proxyServer.Contains("corp", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(new ForensicFinding(
                    Severity.Medium,
                    Category,
                    "Manual proxy configured (possible traffic redirection)",
                    $"HKCU:{internetSettingsPath}",
                    context.Options.ScanTimestampUtc,
                    proxyServer));
            }
        }
    }

    private static IEnumerable<string> ResolveUserSids(ScanContext context)
    {
        if (context.Options.TargetUserSids.Count > 0)
        {
            return context.Options.TargetUserSids;
        }

        if (context.Cache.TryGetValue<IReadOnlyCollection<string>>("registryUserSids", out var cached))
        {
            return cached;
        }

        try
        {
            using var hive = RegistryKey.OpenBaseKey(RegistryHive.Users, context.RegistryView);
            var list = hive.GetSubKeyNames()
                .Where(key => key.StartsWith("S-1-5", StringComparison.OrdinalIgnoreCase) && !key.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase))
                .ToList();
            var readOnly = (IReadOnlyCollection<string>)(list.Count == 0 ? Array.Empty<string>() : list.AsReadOnly());
            context.Cache.GetOrAdd("registryUserSids", () => readOnly);
            return readOnly;
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static RegistryKey? OpenKey(RegistryHive hive, RegistryView view, string path)
    {
        try
        {
            return RegistryKey.OpenBaseKey(hive, view).OpenSubKey(path);
        }
        catch
        {
            return null;
        }
    }
}
