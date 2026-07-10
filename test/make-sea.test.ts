import assert from "node:assert/strict";
import { execFile as execFileCb } from "node:child_process";
import { access, copyFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

type GpgScenario = "missing" | "download-fails" | "verify-fails";

const executable = (path: string, body: string): Promise<void> =>
	writeFile(path, `#!/bin/bash\n${body}\n`, { mode: 0o755 });

const runRequiredGpgBuild = async (
	scenario: GpgScenario,
): Promise<{ code: number; stderr: string; extracted: boolean }> => {
	const dir = await mkdtemp(join(tmpdir(), "vault-sea-gpg-"));
	try {
		const project = join(dir, "project");
		const bin = join(dir, "bin");
		const marker = join(dir, "extracted");
		await mkdir(join(project, "build"), { recursive: true });
		await mkdir(bin);
		await copyFile(
			join(process.cwd(), "build", "make-sea.sh"),
			join(project, "build", "make-sea.sh"),
		);

		await Promise.all([
			executable(
				join(bin, "dirname"),
				'case "$1" in */*) printf "%s\\n" "${1%/*}" ;; *) printf ".\\n" ;; esac',
			),
			executable(
				join(bin, "node"),
				`if [ "\${1:-}" = -p ]; then
  case "\${2:-}" in
    *split*) printf '26\\n' ;;
    *execPath*) printf '%s\\n' "$0" ;;
    *) printf '26.5.0\\n' ;;
  esac
elif [ "\${1:-}" = --version ]; then
  printf 'v26.5.0\\n'
elif [ "\${1:-}" = --help ]; then
  printf '%s\\n' '--build-sea'
fi`,
			),
			executable(
				join(bin, "grep"),
				`if [ "\${1:-}" = -aq ]; then exit 1; fi
if [ "\${1:-}" = -q ]; then exit 0; fi
printf '%s\\n' 'abc  node-v26.5.0-linux-x64.tar.gz'`,
			),
			executable(join(bin, "awk"), 'read -r first _; printf "%s\\n" "$first"'),
			executable(
				join(bin, "uname"),
				'if [ "${1:-}" = -s ]; then printf "Linux\\n"; else printf "x86_64\\n"; fi',
			),
			executable(join(bin, "mkdir"), '/bin/mkdir "$@"'),
			executable(
				join(bin, "curl"),
				`url="$2"
out="$4"
case "$url" in
  *.asc)
    if [ "\${STUB_SIGNATURE_DOWNLOAD:-}" = fail ]; then exit 22; fi
    printf 'signature\\n' > "$out"
    ;;
  *SHASUMS256.txt) printf '%s\\n' 'abc  node-v26.5.0-linux-x64.tar.gz' > "$out" ;;
  *) printf 'archive\\n' > "$out" ;;
esac`,
			),
			executable(join(bin, "sha256sum"), `printf '%s  %s\\n' abc "\${1:-}"`),
			executable(join(bin, "tar"), ': > "$TAR_MARKER"'),
			executable(join(bin, "rm"), "exit 0"),
		]);
		if (scenario !== "missing")
			await executable(
				join(bin, "gpg"),
				'if [ "${STUB_GPG_EXIT:-0}" -ne 0 ]; then exit "$STUB_GPG_EXIT"; fi',
			);

		const env = {
			...process.env,
			PATH: bin,
			TAR_MARKER: marker,
			VAULT_SEA_REQUIRE_GPG: "1",
			STUB_SIGNATURE_DOWNLOAD: scenario === "download-fails" ? "fail" : "",
			STUB_GPG_EXIT: scenario === "verify-fails" ? "1" : "0",
		};
		const result = await new Promise<{ code: number; stderr: string }>((resolve, reject) => {
			execFileCb(
				"/bin/bash",
				[join(project, "build", "make-sea.sh")],
				{ cwd: project, env, encoding: "utf8" },
				(err, _stdout, stderr) => {
					if (err && typeof (err as { code?: unknown }).code !== "number") return reject(err);
					resolve({
						code: (err as { code?: number } | null)?.code ?? 0,
						stderr: stderr as string,
					});
				},
			);
		});
		const extracted = await access(marker).then(
			() => true,
			() => false,
		);
		return { ...result, extracted };
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
};

test("required GPG build fails before extraction when gpg is unavailable", async () => {
	const result = await runRequiredGpgBuild("missing");
	assert.equal(result.code, 1);
	assert.match(result.stderr, /VAULT_SEA_REQUIRE_GPG=1 but gpg is not available/);
	assert.equal(result.extracted, false);
});

test("required GPG build fails before extraction when the signature download fails", async () => {
	const result = await runRequiredGpgBuild("download-fails");
	assert.equal(result.code, 1);
	assert.match(result.stderr, /SHASUMS256\.txt\.asc could not be downloaded/);
	assert.equal(result.extracted, false);
});

test("required GPG build fails before extraction when signature verification fails", async () => {
	const result = await runRequiredGpgBuild("verify-fails");
	assert.equal(result.code, 1);
	assert.match(result.stderr, /GPG verification of SHASUMS256\.txt failed/);
	assert.equal(result.extracted, false);
});
