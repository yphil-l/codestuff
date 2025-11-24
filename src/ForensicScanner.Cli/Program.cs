using ForensicScanner.Core.Admin;
using ForensicScanner.Core.Models;
using ForensicScanner.Core.Scanning;
using ForensicScanner.Core.Services;
using System.Diagnostics;

namespace ForensicScanner.Cli;

internal class Program
{
    private static async Task<int> Main(string[] args)
    {
        Console.WriteLine("Windows Forensic Scanner v1.0");
        Console.WriteLine("===============================================================");

        if (!AdminChecker.IsRunningAsAdministrator())
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(AdminChecker.GetAdminErrorMessage());
            Console.ResetColor();
            return 1;
        }

        bool launchGui = args.Contains("--gui", StringComparer.OrdinalIgnoreCase);
        
        if (launchGui)
        {
            LaunchGui();
            return 0;
        }

        var request = BuildScanRequest();
        if (request == null)
            return 1;

        await RunScanAsync(request);
        return 0;
    }

    private static void LaunchGui()
    {
        try
        {
            var guiExePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ForensicScanner.Gui.exe");
            if (!File.Exists(guiExePath))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"GUI executable not found at {guiExePath}");
                Console.WriteLine("Please ensure ForensicScanner.Gui.exe is in the same directory.");
                Console.ResetColor();
                return;
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = guiExePath,
                UseShellExecute = true,
                Verb = "runas"
            });
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Failed to launch GUI: {ex.Message}");
            Console.ResetColor();
        }
    }

    private static ScanRequest? BuildScanRequest()
    {
        Console.WriteLine("\nSelect Scan Depth:");
        Console.WriteLine("  1 - Light (Prefetch, Event Logs, Run Keys, Quick Memory)");
        Console.WriteLine("  2 - Medium (Light + Amcache, USN Journal, Task Scheduler, BAM, UserAssist)");
        Console.WriteLine("  3 - Deep (Medium + VSS, ADS, Full Memory Scan)");
        Console.Write("\nEnter depth (1-3): ");

        if (!int.TryParse(Console.ReadLine(), out var choice) || choice < 1 || choice > 3)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("Invalid selection.");
            Console.ResetColor();
            return null;
        }

        var depth = choice switch
        {
            1 => ScanDepth.Light,
            2 => ScanDepth.Medium,
            3 => ScanDepth.Deep,
            _ => ScanDepth.Light
        };

        Console.Write("\nEnter custom registry keys (comma-separated, or press Enter to skip): ");
        var registryInput = Console.ReadLine()?.Trim() ?? string.Empty;
        var registryKeys = string.IsNullOrWhiteSpace(registryInput)
            ? Array.Empty<string>()
            : registryInput.Split(',').Select(k => k.Trim()).Where(k => !string.IsNullOrWhiteSpace(k)).ToArray();

        Console.Write("\nEnter custom file/directory paths (comma-separated, or press Enter to skip): ");
        var filePathInput = Console.ReadLine()?.Trim() ?? string.Empty;
        var filePaths = string.IsNullOrWhiteSpace(filePathInput)
            ? Array.Empty<string>()
            : filePathInput.Split(',').Select(p => p.Trim()).Where(p => !string.IsNullOrWhiteSpace(p)).ToArray();

        Console.Write("\nSave report to file? (Y/N): ");
        var saveReport = Console.ReadLine()?.Trim().Equals("Y", StringComparison.OrdinalIgnoreCase) ?? false;

        string? reportPath = null;
        if (saveReport)
        {
            reportPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                $"ForensicScanReport_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
            );
            Console.WriteLine($"Report will be saved to: {reportPath}");
        }

        return new ScanRequest
        {
            Depth = depth,
            CustomRegistryKeys = registryKeys,
            CustomFilePaths = filePaths,
            ReportOutputPath = reportPath,
            AppendTimestampToReport = true
        };
    }

    private static async Task RunScanAsync(ScanRequest request)
    {
        Console.WriteLine("\n===============================================================");
        Console.WriteLine("Starting Scan...");
        Console.WriteLine("===============================================================\n");

        var scanner = new ForensicScannerService();
        scanner.ProgressChanged += (sender, e) =>
        {
            Console.WriteLine($"[{e.PercentComplete}%] {e.Message}");
        };

        var result = await scanner.ScanAsync(request, CancellationToken.None);

        Console.WriteLine("\n===============================================================");
        Console.WriteLine("Scan Complete");
        Console.WriteLine("===============================================================\n");

        DisplayResults(result);

        if (request.SaveReportToFile && !string.IsNullOrWhiteSpace(request.ReportOutputPath))
        {
            var reportGenerator = new ScanReportGenerator();
            reportGenerator.SaveReportToFile(result, request.ReportOutputPath);
            Console.WriteLine($"\nReport saved to: {request.ReportOutputPath}");
        }

        Console.WriteLine("\nPress any key to exit...");
        Console.ReadKey();
    }

    private static void DisplayResults(ScanResult result)
    {
        Console.WriteLine($"Duration: {result.Duration}");
        Console.WriteLine($"Summary: {result.Statistics}");
        Console.WriteLine();

        foreach (SeverityLevel severity in Enum.GetValues(typeof(SeverityLevel)))
        {
            var findings = result.Findings.Where(f => f.Severity == severity).ToList();
            if (!findings.Any())
                continue;

            var color = severity switch
            {
                SeverityLevel.Normal => ConsoleColor.Gray,
                SeverityLevel.SlightlySus => ConsoleColor.Yellow,
                SeverityLevel.VerySus => ConsoleColor.Magenta,
                SeverityLevel.Cheat => ConsoleColor.Red,
                _ => ConsoleColor.White
            };

            Console.ForegroundColor = color;
            Console.WriteLine($"\n[{severity}] Findings ({findings.Count})");
            Console.WriteLine(new string('-', 60));
            Console.ResetColor();

            foreach (var finding in findings.Take(10))
            {
                Console.WriteLine(finding.ToString());
                Console.WriteLine();
            }

            if (findings.Count > 10)
            {
                Console.WriteLine($"... and {findings.Count - 10} more {severity} findings.");
            }
        }

        if (result.Errors.Any())
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("\nErrors:");
            foreach (var error in result.Errors)
            {
                Console.WriteLine(error);
            }
            Console.ResetColor();
        }
    }
}
