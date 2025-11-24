using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace ForensicScanner.Core.Utilities;

public static class RegistryKeyExtensions
{
    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME
    {
        public uint dwLowDateTime;
        public uint dwHighDateTime;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegQueryInfoKey(
        SafeRegistryHandle hKey,
        StringBuilder? lpClass,
        ref uint lpcClass,
        IntPtr lpReserved,
        out uint lpcSubKeys,
        out uint lpcMaxSubKeyLen,
        out uint lpcMaxClassLen,
        out uint lpcValues,
        out uint lpcMaxValueNameLen,
        out uint lpcMaxValueLen,
        out uint lpcbSecurityDescriptor,
        out FILETIME lpftLastWriteTime);

    public static DateTimeOffset? TryGetLastWriteTimeUtc(this RegistryKey key)
    {
        if (!OperatingSystem.IsWindows())
            return null;

        var handle = key.Handle;
        uint length = 0;
        FILETIME fileTime;

        var result = RegQueryInfoKey(
            handle,
            null,
            ref length,
            IntPtr.Zero,
            out _,
            out _,
            out _,
            out _,
            out _,
            out _,
            out _,
            out fileTime);

        if (result != 0)
            return null;

        var fileTimeLong = ((long)fileTime.dwHighDateTime << 32) + fileTime.dwLowDateTime;
        return DateTimeOffset.FromFileTime(fileTimeLong);
    }
}
