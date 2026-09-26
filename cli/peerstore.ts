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

import {
	entryHash,
	replay,
	validRootGenesis,
	type LogEntry,
	type Membership,
} from "../core/authlog.ts";
import type { GrantRow, OpEnvelope, VersionVector } from "../core/protocol.ts";
import { verifiableRotations, type RotationRecord } from "../core/rotation.ts";
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

	maxSeq(teamId: string, deviceId: string): number {
		return this.mine(teamId) ? this.store.maxSeqFor(deviceId) : 0;
	}

	opsSince(teamId: string, vector: VersionVector): OpEnvelope[] {
		return this.mine(teamId) ? this.store.opsSince(vector) : [];
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

	// Membership from this device's auth log, memoized by entry count (the log
	// only grows). Shared with the peer server's op/rotation/grant checks.
	private memberCache: { count: number; membership: Membership | undefined } | undefined;
	membership(): Membership | undefined {
		const count = this.store.authHashes().length;
		if (this.memberCache?.count !== count) {
			let membership: Membership | undefined;
			try {
				membership = replay(this.store.authLog(), this.vaultId);
			} catch {
				membership = undefined; // no valid genesis yet: nothing is authorized
			}
			this.memberCache = { count, membership };
		}
		return this.memberCache.membership;
	}

	// Stored rotations that verify (see verifiableRotations): only these are
	// served and counted as held, so a pusher's genuine record for a slot holding
	// a bogus one is requested and replaces it (Store.putRotation overwrites).
	private rotationRows(): Array<{ id: string; record: string }> {
		return verifiableRotations(this.store.rotations(), this.membership());
	}

	rotationsExcept(teamId: string, have: Set<string>): string[] {
		if (!this.mine(teamId)) return [];
		return this.rotationRows()
			.filter((r) => !have.has(r.id))
			.map((r) => r.record);
	}

	authLacking(teamId: string, hashes: string[]): string[] {
		if (!this.mine(teamId)) return [];
		const held = new Set(this.store.authHashes());
		return hashes.filter((h) => !held.has(h));
	}

	rotationsLacking(teamId: string, ids: string[]): string[] {
		if (!this.mine(teamId)) return [];
		const held = new Set(this.rotationRows().map((r) => r.id));
		return ids.filter((id) => !held.has(id));
	}

	putGrant(teamId: string, g: GrantRow): void {
		if (this.mine(teamId)) this.store.putGrant(teamId, g);
	}

	allGrants(teamId: string): GrantRow[] {
		return this.mine(teamId) ? this.store.allGrants(teamId) : [];
	}
}
