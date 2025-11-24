using System.Text;
using ForensicScanner.Core.Models;

namespace ForensicScanner.Core.Services;

public class ScanReportGenerator
{
    public string GenerateReportText(ScanResult result)
    {
        var sb = new StringBuilder();

        sb.AppendLine("===============================================================");
        sb.AppendLine("Forensic Scanner Report");
        sb.AppendLine($"Generated at: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Scan Depth: {result.Depth}");
        sb.AppendLine($"Duration: {result.Duration}");
        sb.AppendLine($"Findings Summary: {result.Statistics}");
        sb.AppendLine("===============================================================");
        sb.AppendLine();

        foreach (SeverityLevel severity in Enum.GetValues(typeof(SeverityLevel)))
        {
            var findings = result.Findings.Where(f => f.Severity == severity).ToList();
            if (!findings.Any())
                continue;

            sb.AppendLine($"[{severity}] Findings ({findings.Count})");
            sb.AppendLine(new string('-', 60));

            foreach (var finding in findings)
            {
                sb.AppendLine(finding.ToString());
                sb.AppendLine();
            }
        }

        if (result.Errors.Any())
        {
            sb.AppendLine("Errors:");
            foreach (var error in result.Errors)
            {
                sb.AppendLine(error);
            }
        }

        return sb.ToString();
    }

    public void SaveReportToFile(ScanResult result, string filePath)
    {
        try
        {
            var directory = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var reportText = GenerateReportText(result);
            File.WriteAllText(filePath, reportText);
        }
        catch (Exception ex)
        {
            result.AddError($"Failed to save report: {ex.Message}");
        }
    }
}
