using ForensicScanner.Core.Models;
using ForensicScanner.Core.Scanning;
using ForensicScanner.Core.Services;

namespace ForensicScanner.Gui;

public partial class MainForm : Form
{
    private readonly ForensicScannerService _scanner;
    private CancellationTokenSource? _cancellationTokenSource;
    private ScanResult? _lastResult;

    public MainForm()
    {
        InitializeComponent();
        _scanner = new ForensicScannerService();
        _scanner.ProgressChanged += OnScanProgressChanged;
    }

    private async void BtnStartScan_Click(object sender, EventArgs e)
    {
        var depth = radioLight.Checked ? ScanDepth.Light :
                    radioMedium.Checked ? ScanDepth.Medium :
                    ScanDepth.Deep;

        var customRegistryKeys = txtCustomRegistryKeys.Text
            .Split(new[] { ',', ';', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(k => k.Trim())
            .Where(k => !string.IsNullOrWhiteSpace(k))
            .ToArray();

        var customFilePaths = txtCustomFilePaths.Text
            .Split(new[] { ',', ';', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Trim())
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .ToArray();

        var request = new ScanRequest
        {
            Depth = depth,
            CustomRegistryKeys = customRegistryKeys,
            CustomFilePaths = customFilePaths
        };

        btnStartScan.Enabled = false;
        btnCancelScan.Enabled = true;
        progressBar.Value = 0;
        resultsTextBox.Clear();

        _cancellationTokenSource = new CancellationTokenSource();

        try
        {
            _lastResult = await _scanner.ScanAsync(request, _cancellationTokenSource.Token);
            DisplayResults(_lastResult);
        }
        catch (OperationCanceledException)
        {
            resultsTextBox.AppendText("Scan was cancelled.\n");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Scan failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            btnStartScan.Enabled = true;
            btnCancelScan.Enabled = false;
            progressBar.Value = 100;
        }
    }

    private void BtnCancelScan_Click(object sender, EventArgs e)
    {
        _cancellationTokenSource?.Cancel();
    }

    private void BtnSaveReport_Click(object sender, EventArgs e)
    {
        if (_lastResult == null)
        {
            MessageBox.Show("No scan results to save.", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        using var dialog = new SaveFileDialog
        {
            Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
            DefaultExt = "txt",
            FileName = $"ForensicScanReport_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
        };

        if (dialog.ShowDialog() == DialogResult.OK)
        {
            var generator = new ScanReportGenerator();
            generator.SaveReportToFile(_lastResult, dialog.FileName);
            MessageBox.Show($"Report saved to:\n{dialog.FileName}", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }

    private void OnScanProgressChanged(object? sender, ProgressEventArgs e)
    {
        if (InvokeRequired)
        {
            Invoke(new Action<object?, ProgressEventArgs>(OnScanProgressChanged), sender, e);
            return;
        }

        lblStatus.Text = e.Message;
        progressBar.Value = e.PercentComplete;
    }

    private void DisplayResults(ScanResult result)
    {
        resultsTextBox.Clear();
        resultsTextBox.AppendText($"Scan Duration: {result.Duration}\n");
        resultsTextBox.AppendText($"Summary: {result.Statistics}\n\n");

        foreach (SeverityLevel severity in Enum.GetValues(typeof(SeverityLevel)))
        {
            var findings = result.Findings.Where(f => f.Severity == severity).ToList();
            if (!findings.Any())
                continue;

            var color = severity switch
            {
                SeverityLevel.Normal => Color.Gray,
                SeverityLevel.SlightlySus => Color.Orange,
                SeverityLevel.VerySus => Color.Magenta,
                SeverityLevel.Cheat => Color.Red,
                _ => Color.Black
            };

            resultsTextBox.SelectionStart = resultsTextBox.TextLength;
            resultsTextBox.SelectionLength = 0;
            resultsTextBox.SelectionColor = color;
            resultsTextBox.AppendText($"\n[{severity}] Findings ({findings.Count})\n");
            resultsTextBox.AppendText(new string('-', 60) + "\n");
            resultsTextBox.SelectionColor = resultsTextBox.ForeColor;

            foreach (var finding in findings.Take(20))
            {
                resultsTextBox.AppendText($"{finding}\n\n");
            }

            if (findings.Count > 20)
            {
                resultsTextBox.AppendText($"... and {findings.Count - 20} more {severity} findings.\n");
            }
        }

        if (result.Errors.Any())
        {
            resultsTextBox.SelectionColor = Color.Red;
            resultsTextBox.AppendText("\nErrors:\n");
            resultsTextBox.SelectionColor = resultsTextBox.ForeColor;
            foreach (var error in result.Errors)
            {
                resultsTextBox.AppendText($"{error}\n");
            }
        }
    }
}
