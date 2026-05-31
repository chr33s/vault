// Decodable mirrors of the CLI's --json payloads (cli/main.ts `emit(...)` shapes).
// Only the fields the UI consumes are modeled; "ok" is handled by VaultCLI.

import Foundation

struct ItemSummary: Decodable, Identifiable, Hashable {
	let itemId: String
	let title: String?
	var id: String { itemId }
	var displayTitle: String { title ?? itemId }
}

struct ListResponse: Decodable {
	let items: [ItemSummary]
}

struct ItemDetail: Decodable {
	let title: String
	let itemId: String
	let fields: [String: String]
	let passwords: [String]
}

struct AddResponse: Decodable {
	let title: String
	let itemId: String
}

struct SyncResponse: Decodable {
	let pulled: Int
	let pushed: Int
	let catchUpEpoch: Int?
}

// `auth`: this device's Token A (base64), to be shown as a QR to an enrolled device.
struct AuthResponse: Decodable {
	let tokenA: String
	let deviceId: String
}

// `device-confirm` / `join`: the short authentication string to compare aloud.
struct ConfirmResponse: Decodable {
	let sas: String
}

struct VaultsResponse: Decodable {
	let vaults: [String]
}

// `init`: the freshly created vault's identifiers.
struct InitResponse: Decodable {
	let vaultId: String
	let userId: String
	let deviceId: String
}

// `device-add` / `share`: the SAS to verify aloud plus the QR bundle to hand back.
struct AddDeviceResponse: Decodable {
	let sas: String
	let tokenB: String
}

// `invite`: a joiner's Invite Token (base64), to be given to a vault admin.
struct InviteResponse: Decodable {
	let inviteToken: String
	let userId: String
}

// `share`: the admin's response — SAS + the Join Token to give back to the joiner.
struct ShareResponse: Decodable {
	let sas: String
	let joinToken: String
}

// `join`: the joiner confirms — their new userID and the SAS to verify with the admin.
struct JoinResponse: Decodable {
	let userId: String
	let sas: String
}
