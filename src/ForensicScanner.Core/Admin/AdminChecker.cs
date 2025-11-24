using System.Runtime.InteropServices;
using System.Security.Principal;

namespace ForensicScanner.Core.Admin;

public static class AdminChecker
{
    public static bool IsRunningAsAdministrator()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return true;

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

    public static string GetAdminErrorMessage()
    {
        return @"
===============================================================
ERROR: Administrator Privileges Required
===============================================================

This application requires Administrator privileges to access 
forensic artifacts such as:
  - System Registry Hives
  - Event Logs
  - Prefetch files
  - Process memory
  - Volume Shadow Copies
  - USN Journal

Please run this application as Administrator by:
  1. Right-clicking the executable
  2. Select ""Run as administrator""
  
Or from an elevated command prompt.
===============================================================
";
    }
}
