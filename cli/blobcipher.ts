// The shape every keystore tier implements (spec §3.5): an OS/hardware facility
// that seals bytes bound to this machine/user/credential and hands back a blob
// the CLI persists on disk via makeBlobKeyStore (cli/keystore.ts). Defined in
// its own dependency-free module so keystore.ts, tpm2/provider.ts, and hello.ts
// all implement ONE type instead of hand-mirrored copies (the provider modules
// can't import keystore.ts — it imports them).
//
// `name` lets a backend bind the blob to the keystore id (systemd-creds --name,
// hello's AEAD additional data); backends that don't need it ignore the extra
// argument. `bindingMode` is a provider-specific binding the engine persists so
// unlock can rebuild the cipher in the same mode the blob was sealed under.
export type BlobCipher = {
	available(): Promise<boolean>;
	protect(plaintext: Buffer, name?: string): Promise<Buffer>;
	unprotect(blob: Buffer, name?: string): Promise<Buffer>;
	bindingMode?(): string | undefined;
};
