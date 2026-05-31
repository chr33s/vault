// Live QR scanning for inbound enrollment tokens (plan §9, §12a Step 3). An
// AVCaptureSession feeds an AVCaptureMetadataOutput filtered to .qr; the first
// decoded payload is handed back via the callback. Wrapped as an
// NSViewRepresentable so SwiftUI can host the camera preview. Requires the
// com.apple.security.device.camera entitlement + NSCameraUsageDescription (see
// Resources/), and the user's one-time TCC camera grant.

import AVFoundation
import AppKit
import SwiftUI

final class CameraScannerView: NSView, AVCaptureMetadataOutputObjectsDelegate {
	private let session = AVCaptureSession()
	private let previewLayer = AVCaptureVideoPreviewLayer()
	private let onScan: (String) -> Void
	private let onUnavailable: () -> Void
	private var handled = false

	init(onScan: @escaping (String) -> Void, onUnavailable: @escaping () -> Void) {
		self.onScan = onScan
		self.onUnavailable = onUnavailable
		super.init(frame: .zero)
		wantsLayer = true
		configure()
	}

	required init?(coder: NSCoder) { fatalError("init(coder:) unused") }

	private func configure() {
		// No camera, no device input, or a denied TCC grant all land here — tell the
		// host so it can surface the paste fallback instead of a blank black preview.
		guard
			let device = AVCaptureDevice.default(for: .video),
			let input = try? AVCaptureDeviceInput(device: device),
			session.canAddInput(input)
		else {
			DispatchQueue.main.async { [onUnavailable] in onUnavailable() }
			return
		}
		session.addInput(input)

		let output = AVCaptureMetadataOutput()
		guard session.canAddOutput(output) else {
			DispatchQueue.main.async { [onUnavailable] in onUnavailable() }
			return
		}
		session.addOutput(output)
		output.setMetadataObjectsDelegate(self, queue: .main)
		output.metadataObjectTypes = [.qr]

		previewLayer.session = session
		previewLayer.videoGravity = .resizeAspectFill
		layer = previewLayer
		DispatchQueue.global(qos: .userInitiated).async { [session] in session.startRunning() }
	}

	override func layout() {
		super.layout()
		previewLayer.frame = bounds
	}

	func metadataOutput(
		_ output: AVCaptureMetadataOutput,
		didOutput objects: [AVMetadataObject],
		from connection: AVCaptureConnection
	) {
		guard !handled,
			let qr = objects.first as? AVMetadataMachineReadableCodeObject,
			let value = qr.stringValue
		else { return }
		handled = true
		session.stopRunning()
		onScan(value)
	}

	func stop() {
		if session.isRunning { session.stopRunning() }
	}
}

struct CameraScanner: NSViewRepresentable {
	let onScan: (String) -> Void
	var onUnavailable: () -> Void = {}

	func makeNSView(context: Context) -> CameraScannerView {
		CameraScannerView(onScan: onScan, onUnavailable: onUnavailable)
	}
	func updateNSView(_ nsView: CameraScannerView, context: Context) {}
	static func dismantleNSView(_ nsView: CameraScannerView, coordinator: ()) { nsView.stop() }
}

// Camera preview with a manual-paste fallback. Token B / Join Tokens can exceed
// practical QR density (see QRCode.swift) and the camera may be unavailable or
// denied — in either case the user can paste the base64 token text instead.
struct ScanOrPaste: View {
	let prompt: String
	let onToken: (String) -> Void

	@State private var cameraDown = false
	@State private var pasted = ""

	var body: some View {
		VStack(spacing: 10) {
			Text(prompt).font(.callout)
			if !cameraDown {
				CameraScanner(onScan: onToken, onUnavailable: { cameraDown = true })
					.frame(height: 240)
					.clipShape(RoundedRectangle(cornerRadius: 8))
			} else {
				Label("Camera unavailable — paste the token text below", systemImage: "video.slash")
					.font(.callout).foregroundStyle(.secondary)
			}
			DisclosureGroup("Paste token instead") {
				VStack(spacing: 8) {
					TextEditor(text: $pasted)
						.font(.system(.caption2, design: .monospaced))
						.frame(height: 80)
						.overlay(RoundedRectangle(cornerRadius: 6).stroke(.quaternary))
					Button("Use pasted token") {
						let t = pasted.trimmingCharacters(in: .whitespacesAndNewlines)
						if !t.isEmpty { onToken(t) }
					}
					.disabled(pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
				}
			}
		}
	}
}
