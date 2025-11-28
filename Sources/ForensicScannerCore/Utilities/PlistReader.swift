import Foundation

public enum PlistReader {
    public static func propertyList(at url: URL) -> Any? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
    }

    public static func dictionary(at url: URL) -> [String: Any]? {
        propertyList(at: url) as? [String: Any]
    }
}
