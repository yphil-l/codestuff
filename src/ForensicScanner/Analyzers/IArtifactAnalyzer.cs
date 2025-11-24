using ForensicScanner.Models;
using ForensicScanner.Services;

namespace ForensicScanner.Analyzers;

public interface IArtifactAnalyzer
{
    ArtifactCategory Category { get; }

    Task<IReadOnlyCollection<ForensicFinding>> AnalyzeAsync(ScanContext context, CancellationToken cancellationToken);
}
