// Renders an enrollment/sharing token as a QR plus its raw base64 text (plan §9,
// §12a Step 3). Large bundles (Token B / Join Token) may exceed practical QR
// density, so the raw text is always shown for copy/paste as a fallback.

import SwiftUI

struct TokenQRView: View {
	let token: String

	var body: some View {
		VStack(spacing: 8) {
			if let image = QRCode.image(from: token) {
				Image(nsImage: image)
					.interpolation(.none)
					.resizable()
					.scaledToFit()
					.frame(width: 240, height: 240)
			} else {
				Text("Token too large to render as a QR — copy the text below")
					.foregroundStyle(.secondary)
			}
			ScrollView {
				Text(token)
					.font(.system(.caption2, design: .monospaced))
					.textSelection(.enabled)
					.frame(maxWidth: .infinity, alignment: .leading)
			}
			.frame(height: 60)
			Button("Copy token") {
				NSPasteboard.general.clearContents()
				NSPasteboard.general.setString(token, forType: .string)
			}
			.font(.caption)
		}
	}
}
