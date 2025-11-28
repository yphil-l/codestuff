using System.Text.RegularExpressions;

namespace ForensicScanner.Utilities;

public static class KeywordCatalog
{
    public static readonly string[] CheatIndicators =
    {
        "cheat",
        "aim",
        "esp",
        "wallhack",
        "spoof",
        "inject",
        "loader",
        "macro",
        "rage",
        "trigger",
        "bypass",
        "silent",
        "radar",
        "overlay",
        "bot",
        "dll",
        "wh",
        "recoil",
        "antiaim",
        "spinbot",
        "unlock",
        "stealth",
        "clutch",
        "hwid",
        "spoof",
        "sensor"
    };

    public static readonly string[] SuspiciousDirectories =
    {
        "appdata",
        "temp",
        "programdata",
        "public",
        "downloads",
        "\\users",
        "recycle",
        "onedrive",
        "documents"
    };

    public static readonly string[] LogClearingCommands =
    {
        "wevtutil",
        "Clear-EventLog",
        "Clear-Log",
        "Remove-EventLog",
        "forfiles /p %systemroot%\\system32\\winevt\\logs",
        "del %systemroot%\\system32\\winevt"
    };

    public static bool ContainsCheatIndicator(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        return CheatIndicators.Any(keyword => value.Contains(keyword, StringComparison.OrdinalIgnoreCase));
    }

    public static bool ContainsSuspiciousDirectory(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        return SuspiciousDirectories.Any(segment => path.Contains(segment, StringComparison.OrdinalIgnoreCase));
    }

    public static bool LooksLikeNetworkAddress(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        var ipPattern = new Regex(@"\b\d{1,3}(?:\.\d{1,3}){3}\b", RegexOptions.Compiled);
        return ipPattern.IsMatch(input);
    }
}
