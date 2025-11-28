import Foundation

public enum AnalyzerFactory {
    public static func defaultAnalyzers() -> [ArtifactAnalyzer] {
        return [
            PreferencesAnalyzer(),
            DefaultsAnalyzer(),
            LaunchItemAnalyzer(),
            LogsAnalyzer(),
            TrashAnalyzer(),
            ShellHistoryAnalyzer(),
            BrowserAnalyzer(),
            ProcessAnalyzer(),
            SystemPersistenceAnalyzer(),
            UserActivityAnalyzer(),
            ApplicationAnalyzer(),
            KeychainAnalyzer(),
            SecurityPostureAnalyzer(),
            CustomPathAnalyzer()
        ]
    }
}
