// A RelayStorage adapter (spec §8 store-and-forward) backed by a device's OWN
// local replica Store, scoped to a single vault. It lets a device act as a relay
// peer for the §8.6 direct tailnet path: it serves and accepts the same opaque
// op-log plus signed membership/rotation/grant metadata the Cloudflare hub does,
// over the SAME anti-entropy handler (relay/handler.ts) — no decryption, no keys,
// works while the vault is locked.
//
// Requests for any teamId other than this device's own vault are refused (empty /
// no-op), so a tailnet peer that belongs to a *different* vault can never pull or
// inject into this one's log even if it reaches the port and guesses nothing.

import { entryHash, validRootGenesis, type LogEntry } from "../core/authlog.ts";
import {
	rotationId,
	type GrantRow,
	type OpEnvelope,
	type VersionVector,
} from "../core/protocol.ts";
import type { RotationRecord } from "../core/rotation.ts";
import type { Store } from "../core/store.ts";
import type { RelayStorage } from "../relay/handler.ts";

export class PeerStore implements RelayStorage {
	private readonly store: Store;
	private readonly vaultId: string;
	private pinnedGenesisHash: string | undefined;

	constructor(store: Store, vaultId: string) {
		this.store = store;
		this.vaultId = vaultId;
		const genesis = store.authLog().find((e) => validRootGenesis(e, vaultId));
		this.pinnedGenesisHash = genesis && entryHash(genesis);
	}

	private mine(teamId: string): boolean {
		return teamId === this.vaultId;
	}

	putOp(teamId: string, op: OpEnvelope): boolean {
		return this.mine(teamId) ? this.store.putOp(op) : false;
	}

	allOps(teamId: string): OpEnvelope[] {
		return this.mine(teamId) ? this.store.allOps() : [];
	}

	vector(teamId: string): VersionVector {
		return this.mine(teamId) ? this.store.versionVector() : {};
	}

	putAuth(teamId: string, entry: LogEntry): void {
		// Key by the recomputed hash (don't trust the pusher's cached field), matching
		// the relay; the signed chain is re-validated at replay when this device unlocks.
		if (this.mine(teamId)) this.store.appendAuthEntry({ ...entry, hash: entryHash(entry) });
	}

	pinGenesis(teamId: string, entry: LogEntry): boolean {
		if (!this.mine(teamId)) return false;
		if (!validRootGenesis(entry, teamId)) return false;
		const hash = entryHash(entry);
		this.pinnedGenesisHash ??= hash;
		return this.pinnedGenesisHash === hash;
	}

	authExcept(teamId: string, have: Set<string>): LogEntry[] {
		if (!this.mine(teamId)) return [];
		const seen = new Set(have);
		return this.store.authLog().filter((entry) => {
			const hash = entryHash(entry);
			if (
				entry.body.type === "genesis" &&
				(hash !== this.pinnedGenesisHash || !validRootGenesis(entry, teamId))
			)
				return false;
			if (seen.has(hash)) return false;
			seen.add(hash);
			return true;
		});
	}

	putRotation(teamId: string, rec: RotationRecord): void {
		if (this.mine(teamId)) this.store.putRotation(rec.epoch, rec.deviceId, JSON.stringify(rec));
	}

	rotationsExcept(teamId: string, have: Set<string>): string[] {
		if (!this.mine(teamId)) return [];
		return this.store.rotations().filter((r) => {
			const o = JSON.parse(r) as RotationRecord;
			return !have.has(rotationId(o.epoch, o.deviceId));
		});
	}

	putGrant(teamId: string, g: GrantRow): void {
		if (this.mine(teamId)) this.store.putGrant(teamId, g);
	}

	allGrants(teamId: string): GrantRow[] {
		return this.mine(teamId) ? this.store.allGrants(teamId) : [];
	}
}
