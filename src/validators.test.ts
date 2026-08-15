// Unit tests for the admission-mirror validators (pure; node:test, no deps).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
    validateByType,
    validateGatewaySpec,
    validatePluginSpec,
    validateRevocationListSpec,
    isAnchoredRegexp,
    isSha256Hex,
} from "./validators";

test("gateway: two workload identities rejected", () => {
    const f = validateGatewaySpec({ image: {}, workloadIdentity: { aws: {}, gcp: {} } });
    assert.ok(f.some((x) => x.rule === "gateway.workloadIdentity.oneOf"));
});

test("gateway: minimal accepted", () => {
    assert.deepEqual(validateGatewaySpec({ image: { repository: "x", tag: "y" } }), []);
});

test("plugin: tag-only with no cosign rejected", () => {
    const f = validatePluginSpec({ oci: { image: "ghcr.io/x:1.0" }, trust: {} });
    assert.ok(f.some((x) => x.rule === "plugin.trust.anchor"));
});

test("plugin: cosign regexp must be anchored", () => {
    const f = validatePluginSpec({
        oci: { image: "ghcr.io/x:1.0" },
        trust: { cosignIdentity: { certificateIdentityRegexp: "https://github.com/.+", oidcIssuer: "x" } },
    });
    assert.ok(f.some((x) => x.rule === "plugin.cosign.anchoredRegexp"));
});

test("plugin: fully-formed digest-pinned accepted", () => {
    assert.deepEqual(
        validatePluginSpec({
            pluginId: "dev.mcpg.backend.sql",
            pluginClass: "backend",
            version: "1.4.2",
            oci: { image: "ghcr.io/x@sha256:" + "a".repeat(64) },
            trust: { signingKeyRef: { secretName: "k" } },
        }),
        [],
    );
});

test("plugin: bad class + non-reverse-DNS id rejected (adm-3)", () => {
    const f = validatePluginSpec({
        pluginId: "noDotId",
        pluginClass: "frobnicator",
        version: "1.0",
        oci: { image: "ghcr.io/x@sha256:" + "a".repeat(64) },
        trust: { signingKeyRef: { secretName: "k" } },
    });
    assert.ok(f.some((x) => x.rule === "plugin.pluginId.reverseDns"));
    assert.ok(f.some((x) => x.rule === "plugin.pluginClass.known"));
});

test("plugin: missing signingKeyRef rejected (trust-9)", () => {
    const f = validatePluginSpec({ oci: { image: "ghcr.io/x@sha256:" + "a".repeat(64) }, trust: {} });
    assert.ok(f.some((x) => x.rule === "plugin.trust.signingKeyRef.required"));
});

test("revocationList: bad sha + duplicates rejected", () => {
    const f = validateRevocationListSpec({
        version: 1,
        revocations: [{ artifactSha256: "xyz" }, { artifactSha256: "a".repeat(64) }, { artifactSha256: "a".repeat(64) }],
    });
    assert.ok(f.some((x) => x.rule === "revocationList.sha256"));
    assert.ok(f.some((x) => x.rule === "revocationList.noDuplicates"));
});

test("helpers", () => {
    // case-insensitive 64-hex (the operator accepts uppercase — adm-2/trust-5/parity-5).
    assert.equal(isSha256Hex("a".repeat(64)), true);
    assert.equal(isSha256Hex("A".repeat(64)), true);
    assert.equal(isSha256Hex("a".repeat(63)), false);
    assert.equal(isSha256Hex("g".repeat(64)), false);
    assert.equal(isAnchoredRegexp("^x$"), true);
    assert.equal(isAnchoredRegexp("x"), false);
    // RE2-incompatible lookahead rejected to match Go/operator (parity-1).
    assert.equal(isAnchoredRegexp("^(?=.*x).*$"), false);
});

test("dispatch: ours validated, non-MCPG ignored", () => {
    assert.ok(validateByType("kubernetes:mcpg.dev/v1alpha1:MCPGGateway", {}).length > 0);
    assert.deepEqual(validateByType("kubernetes:core/v1:ConfigMap", {}), []);
});
