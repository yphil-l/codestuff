using System.Collections.Concurrent;

namespace ForensicScanner.Services;

public sealed class ArtifactCache
{
    private readonly ConcurrentDictionary<string, object?> _cache = new(StringComparer.OrdinalIgnoreCase);

    public T GetOrAdd<T>(string key, Func<T> factory)
    {
        if (_cache.TryGetValue(key, out var existing) && existing is T typed)
        {
            return typed;
        }

        var created = factory();
        _cache[key] = created;
        return created!;
    }

    public bool TryGetValue<T>(string key, out T? value)
    {
        if (_cache.TryGetValue(key, out var existing) && existing is T typed)
        {
            value = typed;
            return true;
        }

        value = default;
        return false;
    }
}
