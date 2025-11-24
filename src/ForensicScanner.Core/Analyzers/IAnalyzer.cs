using ForensicScanner.Core.Models;

namespace ForensicScanner.Core.Analyzers;

public interface IAnalyzer
{
    string Name { get; }
    ScanDepth RequiredDepth { get; }
    Task<List<Finding>> AnalyzeAsync(ScanContext context);
}
