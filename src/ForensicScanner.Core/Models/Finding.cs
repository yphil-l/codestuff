namespace ForensicScanner.Core.Models;

public class Finding
{
    public SeverityLevel Severity { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Explanation { get; set; } = string.Empty;
    public string ArtifactPath { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public Dictionary<string, string> AdditionalData { get; set; } = new();

    public override string ToString()
    {
        return $"[{Severity}] {Title}\n  {Explanation}\n  Artifact: {ArtifactPath}";
    }
}
