import assert from "node:assert/strict";
import { test } from "node:test";
import { parseDotenv, parseVaultRef } from "../cli/dotenv.ts";

test("parseDotenv: bare key vs empty value vs literal", () => {
	const decls = parseDotenv("BARE\nEMPTY=\nLITERAL=value\n");
	assert.deepEqual(decls, [
		{ key: "BARE", value: undefined }, // resolve from vault by name
		{ key: "EMPTY", value: "" }, // resolve from vault by name
		{ key: "LITERAL", value: "value" }, // pass through verbatim
	]);
});

test("parseDotenv: skips blank lines and comments (whole-line and trailing)", () => {
	const decls = parseDotenv(
		["", "  ", "# a comment", "  # indented comment", "A=1 # trailing comment", "B=2"].join("\n"),
	);
	assert.deepEqual(decls, [
		{ key: "A", value: "1" },
		{ key: "B", value: "2" },
	]);
});

test("parseDotenv: a '#' inside quotes is NOT treated as a comment", () => {
	const decls = parseDotenv(
		['SECRET="p@ss # word"', "OTHER='a#b'", "BARE=ab#cd", "TRAIL=v # c"].join("\n"),
	);
	assert.deepEqual(decls, [
		{ key: "SECRET", value: "p@ss # word" }, // whitespace-preceded # is quoted -> kept
		{ key: "OTHER", value: "a#b" }, // # inside quotes -> kept
		{ key: "BARE", value: "ab#cd" }, // # not preceded by whitespace -> literal
		{ key: "TRAIL", value: "v" }, // unquoted ` #` -> stripped
	]);
});

test("parseDotenv: an apostrophe in an unquoted value does not block comment stripping", () => {
	// Regression guard: a lone ' or unbalanced quote is NOT a quoted span, so the
	// trailing comment is still stripped (matching the original regex behavior).
	const decls = parseDotenv(
		["KEY=it's a value # c", "TOK=don't # note", 'UNBAL="oops # x'].join("\n"),
	);
	assert.deepEqual(decls, [
		{ key: "KEY", value: "it's a value" },
		{ key: "TOK", value: "don't" },
		{ key: "UNBAL", value: '"oops' },
	]);
});

test("parseDotenv: strips matching single/double quotes, honors `export`", () => {
	const decls = parseDotenv(['export DQ="a b"', "export SQ='c d'", "RAW=e f"].join("\n"));
	assert.deepEqual(decls, [
		{ key: "DQ", value: "a b" },
		{ key: "SQ", value: "c d" },
		{ key: "RAW", value: "e f" },
	]);
});

test("parseDotenv: accepts proxy-policy keys (hyphens, leading ?)", () => {
	const decls = parseDotenv(
		["x-api-key=vault://v/item", "?token", "UPSTREAM=https://h"].join("\n"),
	);
	assert.deepEqual(decls, [
		{ key: "x-api-key", value: "vault://v/item" },
		{ key: "?token", value: undefined },
		{ key: "UPSTREAM", value: "https://h" },
	]);
});

test("parseDotenv: ignores malformed lines (no valid key)", () => {
	// A leading digit / lone '=' is not a valid key, so the line is dropped.
	const decls = parseDotenv("1BAD=x\n=oops\nGOOD=y\n");
	assert.deepEqual(decls, [{ key: "GOOD", value: "y" }]);
});

test("parseVaultRef: parses vault://<vault>/<item>[/<field>]", () => {
	assert.deepEqual(parseVaultRef("vault://personal/github"), {
		vault: "personal",
		item: "github",
		field: undefined,
	});
	assert.deepEqual(parseVaultRef("vault://personal/github/username"), {
		vault: "personal",
		item: "github",
		field: "username",
	});
});

test("parseVaultRef: rejects non-vault scheme and under-specified refs", () => {
	assert.equal(parseVaultRef("https://example.com"), undefined);
	assert.equal(parseVaultRef("vault://onlyvault"), undefined); // needs at least vault + item
});

test("parseVaultRef: tolerates extra/leading slashes", () => {
	assert.deepEqual(parseVaultRef("vault:///personal//github/"), {
		vault: "personal",
		item: "github",
		field: undefined,
	});
});
