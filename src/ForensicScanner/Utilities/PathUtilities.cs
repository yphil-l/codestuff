using System.IO;
using System.Linq;

namespace ForensicScanner.Utilities;

public static class PathUtilities
{
    private static readonly string WindowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string ProgramFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    private static readonly string ProgramFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

    public static bool IsUserWritablePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var normalized = path.Replace('/', '\\');
        return KeywordCatalog.SuspiciousDirectories.Any(dir => normalized.Contains(dir, StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsSystemPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        path = path.Replace('/', '\\');
        return path.StartsWith(WindowsDir, StringComparison.OrdinalIgnoreCase)
            || (!string.IsNullOrWhiteSpace(ProgramFiles) && path.StartsWith(ProgramFiles, StringComparison.OrdinalIgnoreCase))
            || (!string.IsNullOrWhiteSpace(ProgramFilesX86) && path.StartsWith(ProgramFilesX86, StringComparison.OrdinalIgnoreCase));
    }

    public static string GetWindowsPath(params string[] segments)
    {
        var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return Path.Combine(new[] { windowsDir }.Concat(segments).ToArray());
    }
}
