// Hybrid Logical Clock (spec §7.1). Provides a monotonic, causally-consistent
// timestamp that is comparable across devices. Serialized as a fixed-width
// string so lexicographic comparison matches logical order.

export type HLC = {
	millis: number; // physical time component
	counter: number; // logical counter for ties within the same millisecond
	deviceId: string; // tiebreak so two devices never produce equal stamps
};

const MILLIS_WIDTH = 15; // ample room for ms timestamps
const MILLIS_MAX = 10 ** MILLIS_WIDTH - 1; // 999999999999999 (~year 33658); beyond
// this the fixed-width encoding would widen and break the lexicographic ==
// logical-order invariant that string comparisons of encoded HLCs rely on.
const COUNTER_WIDTH = 6;
const COUNTER_MAX = 10 ** COUNTER_WIDTH - 1; // 999999; beyond this the fixed-width
// encoding would widen and break lexicographic == logical order, so we carry the
// overflow into the millis component (advancing logical time) instead.
const MAX_FORWARD_DRIFT_MS = 24 * 60 * 60 * 1000;

// Callers that ingest remote state use this before applying it. Keeping the
// policy outside observe() is important: every timestamp that is accepted must
// still advance the clock past the exact receive event for HLC causality.
export const isWithinForwardDrift = (remote: HLC, now: number = Date.now()): boolean =>
	remote.millis <= now + MAX_FORWARD_DRIFT_MS;

export const encodeHLC = (h: HLC): string => {
	if (h.millis > MILLIS_MAX)
		throw new Error(`HLC millis ${h.millis} exceeds encodable width (clock skew?)`);
	return `${String(h.millis).padStart(MILLIS_WIDTH, "0")}:${String(h.counter).padStart(
		COUNTER_WIDTH,
		"0",
	)}:${h.deviceId}`;
};

export const decodeHLC = (s: string): HLC => {
	const [m, c, ...rest] = s.split(":");
	return {
		millis: Number(m),
		counter: Number(c),
		deviceId: rest.join(":"),
	};
};

// Total order: physical time, then counter, then deviceId fingerprint.
export const compareHLC = (a: HLC, b: HLC): number => {
	if (a.millis !== b.millis) return a.millis - b.millis;
	if (a.counter !== b.counter) return a.counter - b.counter;
	return a.deviceId < b.deviceId ? -1 : a.deviceId > b.deviceId ? 1 : 0;
};

export const compareEncoded = (a: string, b: string): number =>
	compareHLC(decodeHLC(a), decodeHLC(b));

// A per-device clock. `now` is injectable for deterministic tests.
export class Clock {
	private lastMillis = 0;
	private counter = 0;
	private readonly deviceId: string;
	private readonly now: () => number;

	constructor(deviceId: string, now: () => number = Date.now) {
		this.deviceId = deviceId;
		this.now = now;
	}

	// Generate the next local timestamp.
	tick(): HLC {
		const phys = this.now();
		if (phys > this.lastMillis) {
			this.lastMillis = phys;
			this.counter = 0;
		} else {
			this.counter += 1;
		}
		this.carryCounter();
		return { millis: this.lastMillis, counter: this.counter, deviceId: this.deviceId };
	}

	// If the per-millisecond counter would overflow its fixed encoding width,
	// carry into millis so timestamps stay strictly increasing and encodable.
	private carryCounter(): void {
		while (this.counter > COUNTER_MAX) {
			this.lastMillis += 1;
			this.counter -= COUNTER_MAX + 1;
		}
	}

	// Merge a remote timestamp, advancing the local clock past it (receive event).
	observe(remote: HLC): HLC {
		const phys = this.now();
		const maxMillis = Math.max(phys, this.lastMillis, remote.millis);
		if (maxMillis === this.lastMillis && maxMillis === remote.millis) {
			this.counter = Math.max(this.counter, remote.counter) + 1;
		} else if (maxMillis === this.lastMillis) {
			this.counter += 1;
		} else if (maxMillis === remote.millis) {
			this.counter = remote.counter + 1;
		} else {
			this.counter = 0;
		}
		this.lastMillis = maxMillis;
		this.carryCounter();
		return { millis: this.lastMillis, counter: this.counter, deviceId: this.deviceId };
	}
}
