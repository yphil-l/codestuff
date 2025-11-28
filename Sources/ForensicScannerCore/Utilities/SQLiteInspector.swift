import Foundation

#if canImport(SQLite3)
import SQLite3
#endif

public struct SQLiteRow {
    public let columns: [String: String]
}

public enum SQLiteInspector {
    public static var isSupported: Bool {
        #if canImport(SQLite3)
        return true
        #else
        return false
        #endif
    }

    public static func fetchRows(databasePath: String, query: String, limit: Int = 50) -> [SQLiteRow] {
        #if canImport(SQLite3)
        var db: OpaquePointer?
        let flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX
        guard sqlite3_open_v2(databasePath, &db, flags, nil) == SQLITE_OK, let database = db else {
            return []
        }
        defer { sqlite3_close(database) }
        var statement: OpaquePointer?
        let limitedQuery = "\(query) LIMIT \(limit)"
        guard sqlite3_prepare_v2(database, limitedQuery, -1, &statement, nil) == SQLITE_OK, let stmt = statement else {
            return []
        }
        defer { sqlite3_finalize(stmt) }
        var rows: [SQLiteRow] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            var columns: [String: String] = [:]
            let columnCount = sqlite3_column_count(stmt)
            for index in 0..<columnCount {
                let name = String(cString: sqlite3_column_name(stmt, index))
                if let textPointer = sqlite3_column_text(stmt, index) {
                    let value = String(cString: textPointer)
                    columns[name] = value
                } else {
                    columns[name] = ""
                }
            }
            rows.append(SQLiteRow(columns: columns))
        }
        return rows
        #else
        return []
        #endif
    }
}
