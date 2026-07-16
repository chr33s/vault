// vault-hello-helper — Windows Hello KeyCredential signer (plan §12b).
//
// The Node CLI's `windows-hello` KeyStore provider (cli/hello.ts) spawns this
// helper to obtain a DETERMINISTIC, Hello-gated signature over a per-blob
// challenge; the CLI derives the DUK wrap key from it as
// HKDF(signature, salt=challenge) -> AES-256-GCM. The helper never sees the DUK
// or the vault — it only signs. KeyCredential private keys are non-exportable
// and TPM-backed where a TPM exists; RequestSignAsync is the moment Windows
// shows the Hello gesture (PIN/face/fingerprint), so `get` is true per-access
// user verification.
//
// Wire protocol (mirrors the macOS vault-helper: base64 on stdin/stdout,
// nothing secret on argv):
//
//   vault-hello-helper available                -> prints "1", exit 0 if Hello
//                                                  is set up here; else exit 1
//   vault-hello-helper sign [--create] <name>   <- base64(challenge) on stdin
//                                               -> base64(signature) on stdout
//
// `--create` (enrollment only) may mint the per-device credential via
// RequestCreateAsync(FailIfExists). Without it, a missing credential is an
// error: the unlock path must surface "cannot unlock — re-enroll", never mint a
// fresh key that silently fails to decrypt existing blobs.
//
// DETERMINISM (load-bearing, spec §3.5): KeyCredentialManager keys are RSA-2048
// signing with PKCS#1 v1.5, which is deterministic for a fixed input — the same
// mechanism Bitwarden/KeePassXC rely on for Hello unlock. The CLI still
// self-tests at enrollment (signs twice, asserts equal) and refuses the tier if
// a platform ever moves to a randomized scheme (RSA-PSS); the documented
// fallback there is a CNG/NCrypt helper that actually decrypts.
//
// VALIDATION BOUNDARY: the CLI-side blob format, wrap crypto, and spawn
// protocol are unit-tested off Windows against a fake-sign oracle and a stub
// helper (test/hello.test.ts); CI compiles this helper and exercises
// `available` on a real Windows runner (no Hello there, so it answers "not
// available" — the gesture paths must be verified on a real Windows host with
// Hello enrolled).

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;

namespace VaultHelloHelper;

internal static class Program
{
	private static int Fail(string message)
	{
		Console.Error.WriteLine("vault-hello-helper: " + message);
		return 1;
	}

	private static async Task<int> Main(string[] args)
	{
		if (args.Length < 1)
		{
			return Fail("usage: vault-hello-helper <available | sign [--create] <name>>");
		}
		switch (args[0])
		{
			case "available":
				// Verify the caller HERE too, not only on `sign`. Otherwise a helper
				// signed with a certificate the caller no longer matches (a publisher
				// rotation between the CLI and helper releases) would report the tier
				// as available, so provider discovery selects windows-hello over
				// windows-dpapi — then every `sign` fails caller-auth: enrollment
				// hard-fails instead of falling back to DPAPI, and an existing vault
				// gets the engine's misleading "key was lost — re-enroll" (which
				// can't fix a cert mismatch). With the check here, a caller that
				// can't sign sees the tier as unavailable and the engine reports the
				// accurate "protected by windows-hello, unavailable here". An unsigned
				// (dev) helper still fails OPEN unless VAULT_HELLO_STRICT (see
				// CallerAuth.Verify), so the dev flow is unchanged. IsSupportedAsync
				// otherwise answers without side effects (no credential, no gesture).
				CallerAuth.Verify();
				if (!await KeyCredentialManager.IsSupportedAsync())
				{
					return 1;
				}
				Console.Out.Write("1");
				return 0;
			case "sign":
			{
				CallerAuth.Verify();
				bool create = Array.IndexOf(args, "--create") >= 0;
				string? name = args.Length >= 2 ? args[^1] : null;
				if (name is null || name.StartsWith("-", StringComparison.Ordinal))
				{
					return Fail("usage: vault-hello-helper sign [--create] <name>");
				}
				return await Sign(name, create);
			}
			default:
				return Fail("unknown command: " + args[0]);
		}
	}

	private static async Task<int> Sign(string name, bool create)
	{
		byte[] challenge;
		try
		{
			challenge = Convert.FromBase64String(Console.In.ReadToEnd().Trim());
		}
		catch (FormatException)
		{
			return Fail("stdin was not valid base64");
		}
		if (challenge.Length == 0)
		{
			return Fail("empty challenge");
		}

		var opened = await KeyCredentialManager.OpenAsync(name);
		var status = opened.Status;
		KeyCredential? credential = status == KeyCredentialStatus.Success ? opened.Credential : null;
		if (credential is null && status == KeyCredentialStatus.NotFound && create)
		{
			// Enrollment: mint the per-device credential (one Hello gesture).
			// FailIfExists keeps a concurrent create from silently replacing a key
			// that existing blobs were wrapped under.
			var created = await KeyCredentialManager.RequestCreateAsync(
				name, KeyCredentialCreationOption.FailIfExists);
			status = created.Status;
			credential = status == KeyCredentialStatus.Success ? created.Credential : null;
		}
		if (credential is null)
		{
			// NotFound / UserCanceled / SecurityDeviceLocked / UserPrefersPassword:
			// a non-zero exit that the CLI maps to "no secret" on the unlock path.
			return Fail("credential unavailable: " + status);
		}

		var result = await credential.RequestSignAsync(
			CryptographicBuffer.CreateFromByteArray(challenge));
		if (result.Status != KeyCredentialStatus.Success)
		{
			return Fail("sign failed: " + result.Status);
		}
		CryptographicBuffer.CopyToByteArray(result.Result, out byte[] signature);
		Console.Out.Write(Convert.ToBase64String(signature));
		return 0;
	}
}

// ---- caller authentication (best-effort; scope mirrors the macOS helper) ----
//
// The Hello gesture authenticates the HUMAN, not the calling code: any process
// running as this user could spawn the helper and, on a reflexive tap, obtain a
// wrap-key signature. When both this helper and its caller carry Authenticode
// signatures, we additionally require the parent process's executable to be
// signed by the SAME publisher certificate (WinVerifyTrust validates the chain;
// thumbprint comparison pins the publisher) — the analog of the macOS helper's
// Team-ID SecRequirement check.
//
// What this does NOT protect: the KeyCredential itself is per-user, not
// per-caller — a same-user process can bypass this helper entirely and call
// KeyCredentialManager itself, presenting its own Hello prompt. The load-bearing
// protection against such an attacker is the Hello USER-PRESENCE gesture (the
// human must approve each signature), not code identity. Treat caller-auth as
// defense-in-depth, not a boundary.
//
// Tradeoffs (deliberate, matching the Swift helper):
//   * Binds to the publisher certificate, not one binary — any of our own signed
//     code qualifies, which is fine for a personal vault.
//   * Parent-PID lookup has a theoretical PID-reuse TOCTOU; sound here because
//     the parent is alive awaiting our exit for the whole call.
//   * An unsigned (dev) helper has no identity to bind to, so enforcement fails
//     OPEN — preserving the `dotnet build` dev flow — UNLESS VAULT_HELLO_STRICT
//     is set, which makes an unsigned helper fail CLOSED. For the guarantee to
//     hold in production, ship the CLI and helper Authenticode-signed (signtool).
internal static class CallerAuth
{
	public static void Verify()
	{
		string self = Environment.ProcessPath
			?? throw new InvalidOperationException("cannot resolve own executable path");
		X509Certificate2? selfCert = SignerCertificate(self);
		if (selfCert is null)
		{
			if (Environment.GetEnvironmentVariable("VAULT_HELLO_STRICT") is not null)
			{
				Console.Error.WriteLine(
					"vault-hello-helper: caller verification required (VAULT_HELLO_STRICT) but this helper is unsigned");
				Environment.Exit(1);
			}
			return; // dev build: no code identity to bind the caller to
		}

		string? caller = ParentExecutablePath();
		X509Certificate2? callerCert = caller is null ? null : SignerCertificate(caller);
		if (callerCert is null || !VerifyAuthenticode(caller!)
			|| !string.Equals(callerCert.Thumbprint, selfCert.Thumbprint, StringComparison.OrdinalIgnoreCase))
		{
			Console.Error.WriteLine(
				"vault-hello-helper: caller is not authorized to use the Windows Hello keystore");
			Environment.Exit(1);
		}
	}

	// The Authenticode signer's certificate, or null when the file is unsigned.
	private static X509Certificate2? SignerCertificate(string path)
	{
		try
		{
			return new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
		}
		catch (CryptographicException)
		{
			return null;
		}
	}

	// Resolve the parent process's executable via the documented Toolhelp32
	// snapshot API (th32ParentProcessID), then Process.MainModule.
	private static string? ParentExecutablePath()
	{
		int parentPid = ParentProcessId(Environment.ProcessId);
		if (parentPid <= 0)
		{
			return null;
		}
		try
		{
			using var parent = Process.GetProcessById(parentPid);
			return parent.MainModule?.FileName;
		}
		catch (Exception e) when (e is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
		{
			return null; // parent gone or unreadable -> treated as unsigned caller
		}
	}

	// WinVerifyTrust with WINTRUST_ACTION_GENERIC_VERIFY_V2: the signature is
	// cryptographically valid and chains to a trusted root. Thumbprint pinning
	// above then binds WHICH publisher; this call binds that the signature is
	// real (a copied certificate without the key can't produce one).
	private static bool VerifyAuthenticode(string path)
	{
		var fileInfo = new WINTRUST_FILE_INFO
		{
			cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
			pcwszFilePath = path,
		};
		var data = new WINTRUST_DATA
		{
			cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
			dwUIChoice = 2, // WTD_UI_NONE
			fdwRevocationChecks = 0, // WTD_REVOKE_NONE (offline-friendly; chain checks still run)
			dwUnionChoice = 1, // WTD_CHOICE_FILE
			dwStateAction = 0, // WTD_STATEACTION_IGNORE
		};
		IntPtr filePtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
		try
		{
			Marshal.StructureToPtr(fileInfo, filePtr, false);
			data.pFile = filePtr;
			Guid action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
			return WinVerifyTrust(IntPtr.Zero, ref action, ref data) == 0;
		}
		finally
		{
			Marshal.FreeHGlobal(filePtr);
		}
	}

	private static int ParentProcessId(int pid)
	{
		IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE)
		{
			return -1;
		}
		try
		{
			var entry = new PROCESSENTRY32 { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32>() };
			if (!Process32First(snapshot, ref entry))
			{
				return -1;
			}
			do
			{
				if (entry.th32ProcessID == (uint)pid)
				{
					return (int)entry.th32ParentProcessID;
				}
			} while (Process32Next(snapshot, ref entry));
			return -1;
		}
		finally
		{
			CloseHandle(snapshot);
		}
	}

	private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
		new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

	private const uint TH32CS_SNAPPROCESS = 0x00000002;
	private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	private struct WINTRUST_FILE_INFO
	{
		public uint cbStruct;
		[MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
		public IntPtr hFile;
		public IntPtr pgKnownSubject;
	}

	[StructLayout(LayoutKind.Sequential)]
	private struct WINTRUST_DATA
	{
		public uint cbStruct;
		public IntPtr pPolicyCallbackData;
		public IntPtr pSIPClientData;
		public uint dwUIChoice;
		public uint fdwRevocationChecks;
		public uint dwUnionChoice;
		public IntPtr pFile;
		public uint dwStateAction;
		public IntPtr hWVTStateData;
		public IntPtr pwszURLReference;
		public uint dwProvFlags;
		public uint dwUIContext;
		public IntPtr pSignatureSettings;
	}

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	private struct PROCESSENTRY32
	{
		public uint dwSize;
		public uint cntUsage;
		public uint th32ProcessID;
		public IntPtr th32DefaultHeapID;
		public uint th32ModuleID;
		public uint cntThreads;
		public uint th32ParentProcessID;
		public int pcPriClassBase;
		public uint dwFlags;
		[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
	}

	[DllImport("wintrust.dll", ExactSpelling = true)]
	private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

	[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
	private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern bool CloseHandle(IntPtr hObject);
}
