using System.Diagnostics;
using System.Text;

namespace ForensicScanner.Core.Utilities;

public static class CommandExecutor
{
    public sealed record CommandResult(int ExitCode, string StandardOutput, string StandardError)
    {
        public bool Succeeded => ExitCode == 0;
    }

    public static CommandResult Run(string fileName, string arguments, int timeoutSeconds = 30)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new CommandResult(1, string.Empty, "Command execution is only supported on Windows hosts.");
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        using var process = new Process { StartInfo = startInfo };        
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data != null)
            {
                stdout.AppendLine(e.Data);
            }
        };

        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data != null)
            {
                stderr.AppendLine(e.Data);
            }
        };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        if (!process.WaitForExit(timeoutSeconds * 1000))
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch
            {
                // ignored
            }

            return new CommandResult(-1, stdout.ToString(), stderr.AppendLine("Command timed out.").ToString());
        }

        return new CommandResult(process.ExitCode, stdout.ToString(), stderr.ToString());
    }
}
