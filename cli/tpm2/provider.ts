// The Linux TPM2 "strong tier" as a BlobCipher: seal the DUK to the TPM (per-access
// when a PIN is set), so makeBlobKeyStore (cli/keystore.ts) handles the on-disk blob
// exactly like the DPAPI/systemd-creds tiers. seal = protect, unseal = open.
//
// PIN: from $VAULT_TPM2_PIN, read at call time. Non-empty -> per-access user
// verification with TPM dictionary-attack lockout. Empty -> at-rest TPM binding
// (sealed under an empty authValue: machine + TPM bound, no per-access secret).
//
// Opt-in: this tier is inert unless $VAULT_TPM2=1, so it never changes the default
// keystore selection on a box that merely has a TPM.

import { platform } from "node:os";
import type { BlobCipher } from "../blobcipher.ts";
import { open as tpmOpen, seal } from "./codec.ts";
import { decodeBlob, encodeBlob } from "./codec.ts";
import { devTpmrm0Transport, socketTransport, tbsTransport, type Transport } from "./transport.ts";

// Default transport by platform: $VAULT_TPM2_SOCKET (a socket TPM, e.g. swtpm) wins
// for testing/headless; else Windows uses TBS (tbs.dll via PowerShell) and Linux
// uses the kernel TPM device /dev/tpmrm0.
const defaultTransport = (): Transport => {
	const sock = process.env.VAULT_TPM2_SOCKET;
	if (sock) return socketTransport(Number(sock));
	return platform() === "win32" ? tbsTransport() : devTpmrm0Transport;
};

export type Tpm2Options = {
	transport?: Transport;
	pin?: () => Buffer; // injectable; default reads $VAULT_TPM2_PIN at call time
	optIn?: () => boolean; // injectable; default requires $VAULT_TPM2=1
};

export const makeTpm2Cipher = (opts: Tpm2Options = {}): BlobCipher => {
	const transport = opts.transport ?? defaultTransport();
	const pin = opts.pin ?? ((): Buffer => Buffer.from(process.env.VAULT_TPM2_PIN ?? "", "utf8"));
	const optIn = opts.optIn ?? ((): boolean => process.env.VAULT_TPM2 === "1");
	return {
		async available(): Promise<boolean> {
			return optIn() && (await transport.available());
		},
		async protect(plaintext: Buffer): Promise<Buffer> {
			const conn = await transport.open();
			try {
				return encodeBlob(await seal((cmd) => conn.submit(cmd), plaintext, pin()));
			} finally {
				await conn.close();
			}
		},
		async unprotect(blob: Buffer): Promise<Buffer> {
			const conn = await transport.open();
			try {
				return await tpmOpen((cmd) => conn.submit(cmd), decodeBlob(blob), pin());
			} finally {
				await conn.close();
			}
		},
	};
};
