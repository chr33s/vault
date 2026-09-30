import Foundation
@testable import VaultCore

// Golden vectors were frozen from the former TypeScript reference; the generator no longer exists.
enum Vectors {
	static let dir: URL = URL(fileURLWithPath: #filePath)
		.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
		.deletingLastPathComponent().appendingPathComponent("protocol/vectors")

	static func load(_ name: String) throws -> JSONValue {
		try JSONValue.parse(Data(contentsOf: dir.appendingPathComponent(name)))
	}

	static func url(_ name: String) -> URL { dir.appendingPathComponent(name) }
}

extension JSONValue {
	func str(_ k: String) -> String { self[k]!.string! }
	func at(_ k: String) -> JSONValue { self[k]! }
	var items: [JSONValue] { array! }
	var strings: [String] { array!.map { $0.string! } }
}

func b64(_ s: String) -> Data { Data(base64: s) }
