// QR rendering for enrollment Tokens A/B (plan §9, §12a Step 3). Uses CoreImage's
// built-in CIQRCodeGenerator — no third-party QR dependency, matching the repo's
// zero-dependency ethos. Tokens are base64 text; very large bundles (Join/Token-B)
// may exceed practical QR density, in which case the UI also exposes the raw text.

import AppKit
import CoreImage
import CoreImage.CIFilterBuiltins

enum QRCode {
	static func image(from string: String, scale: CGFloat = 8) -> NSImage? {
		let filter = CIFilter.qrCodeGenerator()
		filter.message = Data(string.utf8)
		filter.correctionLevel = "M"
		guard let output = filter.outputImage else { return nil }
		let scaled = output.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
		let context = CIContext()
		guard let cg = context.createCGImage(scaled, from: scaled.extent) else { return nil }
		return NSImage(cgImage: cg, size: NSSize(width: scaled.extent.width, height: scaled.extent.height))
	}
}
