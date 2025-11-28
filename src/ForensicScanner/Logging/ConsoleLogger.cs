namespace ForensicScanner.Logging;

public interface ILogger
{
    void Info(string message);
    void Warn(string message);
    void Error(string message);
    void Verbose(string message);
    void SetVerbose(bool enabled);
}

public sealed class ConsoleLogger : ILogger
{
    private readonly object _gate = new();
    private volatile bool _verbose;

    public void SetVerbose(bool enabled) => _verbose = enabled;

    public void Info(string message) => Write("INFO", message, ConsoleColor.Cyan);

    public void Warn(string message) => Write("WARN", message, ConsoleColor.Yellow);

    public void Error(string message) => Write("ERROR", message, ConsoleColor.Red);

    public void Verbose(string message)
    {
        if (!_verbose)
        {
            return;
        }

        Write("VERBOSE", message, ConsoleColor.DarkGray);
    }

    private void Write(string prefix, string message, ConsoleColor color)
    {
        lock (_gate)
        {
            var previous = Console.ForegroundColor;
            Console.ForegroundColor = color;
            Console.Write("[");
            Console.Write(prefix);
            Console.Write("] ");
            Console.ForegroundColor = previous;
            Console.WriteLine(message);
        }
    }
}
