import Foundation

// Output modes (spec §15.1). Text by default; with --json every command emits
// exactly one JSON object on stdout ({"ok":true,...} / {"ok":false,"error":...}).

import VaultCore

#if canImport(Darwin)
	import Darwin
#elseif canImport(Glibc)
	import Glibc
#elseif canImport(Musl)
	import Musl
#elseif canImport(ucrt)
	import ucrt
#endif

var jsonOutput: Bool {
	get { CommandContext.current.json }
	set { CommandContext.current.json = newValue }
}

func writeOut(_ s: String) { CommandContext.current.out(s) }
func writeErr(_ s: String) { CommandContext.current.err(s) }

// Escape control characters a terminal would interpret (ESC, CR, C0/C1, DEL) so
// synced content from another member cannot drive the viewer's terminal. Only
// applied to interactive terminals: a pipe gets the exact stored bytes.
func sanitizeForTTY(_ s: String) -> String {
	var out = String.UnicodeScalarView()
	for u in s.unicodeScalars {
		let v = u.value
		if (v <= 0x08) || (0x0B...0x1F).contains(v) || (0x7F...0x9F).contains(v) {
			let h = String(v, radix: 16)
			out.append(contentsOf: "\\x\(h.count < 2 ? "0" + h : h)".unicodeScalars)
		} else {
			out.append(u)
		}
	}
	return String(out)
}

func isTerminal(_ fd: Int32) -> Bool {
	#if os(Windows)
		_isatty(fd) != 0  // the CRT's name; POSIX `isatty` is a deprecated alias there
	#else
		isatty(fd) != 0
	#endif
}

private func isTTY(_ fd: Int32) -> Bool { CommandContext.current.isProcess && isTerminal(fd) }

func emit(_ text: String, _ data: [JSONMember]) {
	if jsonOutput {
		writeOut(JSONValue.object([JSONMember("ok", .bool(true))] + data).stringify() + "\n")
	} else {
		writeOut(isTTY(1) ? sanitizeForTTY(text) : text)
	}
}

func emitError(_ message: String) {
	if jsonOutput {
		writeOut(JSONValue.obj(["ok": .bool(false), "error": .string(message)]).stringify() + "\n")
	} else {
		writeErr("error: \(isTTY(2) ? sanitizeForTTY(message) : message)\n")
	}
}
