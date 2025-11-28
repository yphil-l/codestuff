using System.Security.Principal;

namespace ForensicScanner.Utilities;

public static class SecurityUtilities
{
    public static bool IsRunningAsAdministrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    public static string Rot13(string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return input;
        }

        Span<char> buffer = input.ToCharArray();
        for (int i = 0; i < buffer.Length; i++)
        {
            buffer[i] = buffer[i] switch
            {
                >= 'a' and <= 'z' => (char)('a' + (buffer[i] - 'a' + 13) % 26),
                >= 'A' and <= 'Z' => (char)('A' + (buffer[i] - 'A' + 13) % 26),
                _ => buffer[i]
            };
        }

        return new string(buffer);
    }
}
