using Microsoft.Win32;
using ForensicScanner.Core.Models;

namespace ForensicScanner.Core.Analyzers;

public class RegistryAnalyzer : IAnalyzer
{
    public string Name => "Registry Run Keys Analyzer";
    public ScanDepth RequiredDepth => ScanDepth.Light;

    private static readonly string[] RunKeyPaths = new[]
    {
        @"Software\Microsoft\Windows\CurrentVersion\Run",
        @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    };

    public Task<List<Finding>> AnalyzeAsync(ScanContext context)
    {
        var findings = new List<Finding>();

        CheckRunKeys(Registry.CurrentUser, "HKCU", findings);
        CheckRunKeys(Registry.LocalMachine, "HKLM", findings);
        
        CheckCustomKeys(context, findings);

        return Task.FromResult(findings);
    }

    private void CheckRunKeys(RegistryKey root, string rootName, List<Finding> findings)
    {
        foreach (var path in RunKeyPaths)
        {
            try
            {
                using var key = root.OpenSubKey(path);
                if (key == null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    var value = key.GetValue(valueName)?.ToString() ?? string.Empty;
                    var fullPath = $@"{rootName}\{path}\{valueName}";

                    var severity = AnalyzeRunKeyEntry(valueName, value);
                    var explanation = GenerateExplanation(severity, valueName, value);

                    findings.Add(new Finding
                    {
                        Severity = severity,
                        Title = $"Run Key: {valueName}",
                        Explanation = explanation,
                        ArtifactPath = fullPath,
                        Category = "Registry Run Keys"
                    });
                }
            }
            catch (UnauthorizedAccessException)
            {
                findings.Add(new Finding
                {
                    Severity = SeverityLevel.Normal,
                    Title = "Registry Access Denied",
                    Explanation = $"Unable to access {rootName}\\{path}. Administrative privileges may be required.",
                    ArtifactPath = $@"{rootName}\{path}",
                    Category = "Registry Run Keys"
                });
            }
            catch (Exception ex)
            {
                findings.Add(new Finding
                {
                    Severity = SeverityLevel.Normal,
                    Title = "Registry Read Error",
                    Explanation = $"Error reading {rootName}\\{path}: {ex.Message}",
                    ArtifactPath = $@"{rootName}\{path}",
                    Category = "Registry Run Keys"
                });
            }
        }
    }

    private void CheckCustomKeys(ScanContext context, List<Finding> findings)
    {
        foreach (var keyPath in context.CustomRegistryKeys)
        {
            try
            {
                var (root, subKeyPath) = ParseRegistryPath(keyPath);
                using var key = root?.OpenSubKey(subKeyPath);
                
                if (key == null)
                {
                    findings.Add(new Finding
                    {
                        Severity = SeverityLevel.SlightlySus,
                        Title = "Custom Registry Key Not Found",
                        Explanation = $"Custom registry key {keyPath} does not exist. May have been deleted.",
                        ArtifactPath = keyPath,
                        Category = "Custom Registry"
                    });
                    continue;
                }

                foreach (var valueName in key.GetValueNames())
                {
                    var value = key.GetValue(valueName)?.ToString() ?? string.Empty;
                    findings.Add(new Finding
                    {
                        Severity = SeverityLevel.Normal,
                        Title = $"Custom Key Found: {valueName}",
                        Explanation = $"Custom registry key exists with value: {value}",
                        ArtifactPath = $@"{keyPath}\{valueName}",
                        Category = "Custom Registry"
                    });
                }
            }
            catch (Exception ex)
            {
                findings.Add(new Finding
                {
                    Severity = SeverityLevel.Normal,
                    Title = "Custom Registry Key Error",
                    Explanation = $"Error accessing {keyPath}: {ex.Message}",
                    ArtifactPath = keyPath,
                    Category = "Custom Registry"
                });
            }
        }
    }

    private (RegistryKey? root, string subKey) ParseRegistryPath(string path)
    {
        if (path.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase))
            return (Registry.LocalMachine, path.Substring(5));
        if (path.StartsWith("HKEY_LOCAL_MACHINE\\", StringComparison.OrdinalIgnoreCase))
            return (Registry.LocalMachine, path.Substring(19));
        if (path.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase))
            return (Registry.CurrentUser, path.Substring(5));
        if (path.StartsWith("HKEY_CURRENT_USER\\", StringComparison.OrdinalIgnoreCase))
            return (Registry.CurrentUser, path.Substring(18));
        if (path.StartsWith("HKCR\\", StringComparison.OrdinalIgnoreCase))
            return (Registry.ClassesRoot, path.Substring(5));
        if (path.StartsWith("HKU\\", StringComparison.OrdinalIgnoreCase))
            return (Registry.Users, path.Substring(4));
        
        return (null, path);
    }

    private SeverityLevel AnalyzeRunKeyEntry(string name, string value)
    {
        var lowerValue = value.ToLowerInvariant();
        
        if (lowerValue.Contains("temp") || lowerValue.Contains("appdata\\local\\temp"))
            return SeverityLevel.VerySus;
        
        if (lowerValue.Contains("powershell") || lowerValue.Contains("cmd.exe") || lowerValue.Contains("wscript") || lowerValue.Contains("cscript"))
            return SeverityLevel.SlightlySus;
        
        if (!File.Exists(ExtractFilePath(value)))
            return SeverityLevel.VerySus;
        
        return SeverityLevel.Normal;
    }

    private string GenerateExplanation(SeverityLevel severity, string name, string value)
    {
        return severity switch
        {
            SeverityLevel.VerySus when !File.Exists(ExtractFilePath(value)) => 
                $"Run key '{name}' points to non-existent file, indicating possible cleanup or malicious entry removal.",
            SeverityLevel.VerySus => 
                $"Run key '{name}' points to suspicious location (Temp folder), commonly used by malware.",
            SeverityLevel.SlightlySus => 
                $"Run key '{name}' executes a script interpreter which could be used for evasion.",
            _ => 
                $"Run key '{name}' appears normal and points to valid executable."
        };
    }

    private string ExtractFilePath(string value)
    {
        value = value.Trim().Trim('"');
        var spaceIndex = value.IndexOf(' ');
        if (spaceIndex > 0)
            value = value.Substring(0, spaceIndex);
        return value;
    }
}
