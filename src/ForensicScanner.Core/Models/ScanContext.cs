namespace ForensicScanner.Core.Models;

public sealed class ScanContext
{
    public ScanContext(ScanRequest request, CancellationToken cancellationToken)
    {
        Request = request;
        CancellationToken = cancellationToken;
        StartedAt = DateTimeOffset.Now;
    }

    public ScanRequest Request { get; }
    public CancellationToken CancellationToken { get; }
    public DateTimeOffset StartedAt { get; }

    public IReadOnlyCollection<string> CustomRegistryKeys => Request.CustomRegistryKeys;
    public IReadOnlyCollection<string> CustomFilePaths => Request.CustomFilePaths;
}
