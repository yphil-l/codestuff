using ForensicScanner.Logging;
using ForensicScanner.Models;
using ForensicScanner.Options;
using Microsoft.Win32;

namespace ForensicScanner.Services;

public sealed class ScanContext
{
    public ScanContext(ScanOptions options, ILogger logger, SystemInformation systemInformation, ArtifactCache cache)
    {
        Options = options;
        Logger = logger;
        SystemInformation = systemInformation;
        Cache = cache;
    }

    public ScanOptions Options { get; }

    public ILogger Logger { get; }

    public SystemInformation SystemInformation { get; }

    public ArtifactCache Cache { get; }

    public RegistryView RegistryView => Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32;
}
