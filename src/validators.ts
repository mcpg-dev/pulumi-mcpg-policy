// Admission-mirror validation helpers — PURE functions so they can be shared
// by the CrossGuard pack (preview-time) and the contract corpus, and unit
// tested without a Pulumi runtime. Mirror k8s/operator/src/admission/validators/.

export interface Finding {
    rule: string;
    message: string;
}

const blank = (s: any): boolean => typeof s !== "string" || s.trim() === "";

// pluginClass values the operator accepts (mcpg_plugin_protocol::abi::ALL_KINDS,
// the single source of truth in libs/plugin-protocol/src/abi.rs).
const KNOWN_PLUGIN_CLASSES = [
    "tool_gate", "transform", "identity_provider", "backend", "watch_strategy",
    "http_route", "audit_sink", "log_sink", "telemetry_sink", "metrics_sink",
    "store", "cache", "secret_provider", "config_provider", "policy_engine",
    "cluster", "transport", "catalog_provider", "credential_issuer",
    "approval_notifier", "content_store",
];

// Constructs RE2 (the Go provider + the Rust `regex` crate the operator uses)
// cannot compile but JS RegExp can — lookahead/lookbehind + back-references.
// Rejecting them keeps the Pulumi verdict identical to the operator.
const RE2_INCOMPATIBLE = /\(\?<?[=!]|\\[1-9]|\\k</;

export function isSha256Hex(s: string): boolean {
    // The operator accepts any 64 ascii-hexdigit string (case-insensitive) and
    // lowercases for dedup — uppercase hashes are valid.
    return /^[0-9a-fA-F]{64}$/.test(s);
}

/** cosign certificateIdentityRegexp must be anchored with ^ and $, compile, AND
 *  be RE2-compatible (the operator compiles it with the Rust regex crate). */
export function isAnchoredRegexp(s: string): boolean {
    if (typeof s !== "string" || !s.startsWith("^") || !s.endsWith("$")) return false;
    if (RE2_INCOMPATIBLE.test(s)) return false;
    try {
        new RegExp(s);
        return true;
    } catch {
        return false;
    }
}

const WORKLOAD_IDENTITY_KEYS = ["aws", "gcp", "azure", "spiffe"];
export function countWorkloadIdentities(wi: any): number {
    if (!wi || typeof wi !== "object") return 0;
    return WORKLOAD_IDENTITY_KEYS.filter((k) => wi[k] != null).length;
}

export function findDuplicates<T>(items: T[], key: (t: T) => string): string[] {
    const seen = new Set<string>();
    const dups = new Set<string>();
    for (const it of items) {
        const k = key(it);
        if (seen.has(k)) dups.add(k);
        seen.add(k);
    }
    return [...dups];
}

export function validateGatewaySpec(spec: any): Finding[] {
    const f: Finding[] = [];
    if (!spec?.image) f.push({ rule: "gateway.image.required", message: "spec.image is required" });
    // replicas, when set, must be ≥ 1 (gateway.rs:65). Absent ⇒ defaulted ⇒ ok.
    if (typeof spec?.replicas === "number" && spec.replicas < 1) {
        f.push({ rule: "gateway.replicas.min", message: "spec.replicas must be ≥ 1" });
    }
    if (spec?.workloadIdentity && countWorkloadIdentities(spec.workloadIdentity) > 1) {
        f.push({ rule: "gateway.workloadIdentity.oneOf", message: "workloadIdentity must be exactly one of aws|gcp|azure|spiffe" });
    }
    // Ingress sub-shape (gateway.rs:114-130) when an ingress block is present.
    const ing = spec?.ingress;
    if (ing) {
        if (blank(ing.ingressClassName)) f.push({ rule: "gateway.ingress.ingressClassName", message: "spec.ingress.ingressClassName must not be empty" });
        const hosts: any[] = ing.hosts ?? [];
        if (hosts.length === 0) f.push({ rule: "gateway.ingress.hosts", message: "spec.ingress.hosts must not be empty when ingress is set" });
        hosts.forEach((h, i) => {
            if (blank(h?.host)) f.push({ rule: "gateway.ingress.host", message: `spec.ingress.hosts[${i}].host is empty` });
            if (!Array.isArray(h?.paths) || h.paths.length === 0) f.push({ rule: "gateway.ingress.paths", message: `spec.ingress.hosts[${i}].paths must not be empty` });
        });
    }
    // NB: image.tag-non-empty is enforced by the operator AFTER the mutating
    // webhook defaults an empty/absent tag, so it is not a plan-time reject
    // (would false-reject the rely-on-defaulting path). The per-gateway replica
    // cap (tenant_guard) is a cross-resource, client-backed check — both are
    // intentionally NOT mirrored at plan time.
    return f;
}

export function validatePluginSpec(spec: any): Finding[] {
    const f: Finding[] = [];
    const oci = spec?.oci ?? {};
    const trust = spec?.trust ?? {};

    // Identity + class + version (plugin.rs:56-83).
    if (blank(spec?.pluginId)) f.push({ rule: "plugin.pluginId.nonEmpty", message: "spec.pluginId must not be empty" });
    else if (!spec.pluginId.includes(".")) f.push({ rule: "plugin.pluginId.reverseDns", message: "spec.pluginId is not reverse-DNS form (e.g. dev.mcpg.identity.workload)" });
    if (blank(spec?.version)) f.push({ rule: "plugin.version.nonEmpty", message: "spec.version must not be empty" });
    if (!KNOWN_PLUGIN_CLASSES.includes(spec?.pluginClass)) f.push({ rule: "plugin.pluginClass.known", message: `spec.pluginClass is not a known PluginClass` });

    // OCI image reference shape (plugin.rs:84-99).
    const img = typeof oci.image === "string" ? oci.image.trim() : "";
    if (img === "") f.push({ rule: "plugin.oci.image.nonEmpty", message: "spec.oci.image must not be empty" });
    else {
        if (!img.includes("/")) f.push({ rule: "plugin.oci.image.registry", message: "spec.oci.image lacks a registry component (<registry>/<path>)" });
        if (!img.includes(":") && !img.includes("@")) f.push({ rule: "plugin.oci.image.tagOrDigest", message: "spec.oci.image lacks a tag or digest pin (:tag or @sha256:...)" });
    }

    // Trust anchor: digest pin OR cosign identity (plugin.rs:101-112).
    const digestPinned = img.includes("@sha256:");
    const hasCosign = trust.cosignIdentity != null;
    if (!digestPinned && !hasCosign) {
        f.push({ rule: "plugin.trust.anchor", message: "plugin must be digest-pinned OR carry a cosign identity" });
    }

    // signingKeyRef (Ed25519) is the MANDATORY baseline (plugin.rs:119-124).
    const skr = trust.signingKeyRef;
    if (blank(skr?.secretName)) {
        f.push({ rule: "plugin.trust.signingKeyRef.required", message: "spec.trust.signingKeyRef.secretName is required (Ed25519 signing is the mandatory trust baseline)" });
    }
    // key defaults to release.pub; only an explicit empty key is invalid.
    if (skr && skr.key !== undefined && blank(skr.key)) {
        f.push({ rule: "plugin.trust.signingKeyRef.key", message: "spec.trust.signingKeyRef.key must not be empty when set" });
    }

    // Cosign sub-shape (plugin.rs:126-163).
    if (hasCosign) {
        if (blank(trust.cosignIdentity.certificateIdentityRegexp)) {
            f.push({ rule: "plugin.cosign.regexpNonEmpty", message: "cosign certificateIdentityRegexp must not be empty" });
        } else if (!isAnchoredRegexp(trust.cosignIdentity.certificateIdentityRegexp)) {
            f.push({ rule: "plugin.cosign.anchoredRegexp", message: "cosign certificateIdentityRegexp must be anchored with ^ and $ and compile (RE2)" });
        }
        if (blank(trust.cosignIdentity.oidcIssuer)) {
            f.push({ rule: "plugin.cosign.oidcIssuer", message: "cosign oidcIssuer is required when cosign is set" });
        }
    }

    // SLSA provenance sub-shape (plugin.rs:166-178).
    const slsa = trust.slsaProvenance;
    if (slsa) {
        if (blank(slsa.configMapName)) f.push({ rule: "plugin.slsa.configMapName", message: "spec.trust.slsaProvenance.configMapName must not be empty" });
        if (blank(slsa.sourceUri)) f.push({ rule: "plugin.slsa.sourceUri", message: "spec.trust.slsaProvenance.sourceUri must not be empty" });
        if (blank(slsa.sourceTag)) f.push({ rule: "plugin.slsa.sourceTag", message: "spec.trust.slsaProvenance.sourceTag must not be empty" });
    }
    return f;
}

export function validatePluginSetSpec(spec: any): Finding[] {
    const f: Finding[] = [];
    const entries: any[] = spec?.entries ?? [];
    if (entries.length === 0) f.push({ rule: "pluginSet.entries.nonEmpty", message: "entries must be non-empty" });
    const ids = new Set<string>();
    entries.forEach((e, i) => {
        const id = e?.id;
        if (blank(id)) f.push({ rule: "pluginSet.entries.id.nonEmpty", message: `spec.entries[${i}].id must not be empty` });
        else if (!id.includes(".")) f.push({ rule: "pluginSet.entries.id.reverseDns", message: `spec.entries[${i}].id is not reverse-DNS form` });
        if (blank(e?.pluginRef?.name)) f.push({ rule: "pluginSet.entries.pluginRef.name", message: `spec.entries[${i}].pluginRef.name must not be empty` });
        if (typeof id === "string") ids.add(id);
    });
    const dups = findDuplicates(entries, (e) => String(e?.id));
    if (dups.length) f.push({ rule: "pluginSet.entries.uniqueId", message: `duplicate entry ids: ${dups.join(",")}` });
    // capabilityGrants is a MAP (id → [capabilities]); keys must name an entry
    // id and each grant list must be non-empty (plugin_set.rs:85-100).
    const grants = spec?.capabilityGrants;
    if (grants && typeof grants === "object" && !Array.isArray(grants)) {
        for (const id of Object.keys(grants)) {
            if (!ids.has(id)) f.push({ rule: "pluginSet.capabilityGrants.unknownId", message: `capabilityGrants['${id}'] names an id not in entries` });
            else if (!Array.isArray(grants[id]) || grants[id].length === 0) f.push({ rule: "pluginSet.capabilityGrants.empty", message: `capabilityGrants['${id}'] must not be empty` });
        }
    }
    return f;
}

export function validateRevocationListSpec(spec: any): Finding[] {
    const f: Finding[] = [];
    if (spec?.version !== 1) f.push({ rule: "revocationList.version", message: "version must be 1" });
    const revs: any[] = spec?.revocations ?? [];
    for (const r of revs) {
        if (!isSha256Hex(String(r?.artifactSha256 ?? ""))) {
            f.push({ rule: "revocationList.sha256", message: "artifactSha256 must be 64 hex chars" });
        }
        // empty reason defeats the audit trail (revocation_list.rs:86).
        if (blank(r?.reason)) {
            f.push({ rule: "revocationList.reason", message: "revocation reason must not be empty" });
        }
    }
    // dedup is case-insensitive in the operator (hashes lowercased), so ABCD…
    // and abcd… collide.
    const dups = findDuplicates(revs, (r) => String(r?.artifactSha256 ?? "").toLowerCase());
    if (dups.length) f.push({ rule: "revocationList.noDuplicates", message: `duplicate hashes: ${dups.join(",")}` });
    return f;
}

/** Mirrors the MCPGCluster admission rules (validators/cluster.rs). */
export function validateClusterSpec(spec: any): Finding[] {
    const f: Finding[] = [];
    const backend: string = spec?.backend ?? "single_node";
    const singleNode = backend === "" || backend === "single_node";
    const configEmpty = !spec?.config || Object.keys(spec.config).length === 0;
    if (singleNode && !configEmpty) {
        f.push({ rule: "cluster.singleNode.noConfig", message: "spec.config must be empty for the single_node backend (it takes no parameters)" });
    }
    if (!singleNode && configEmpty) {
        f.push({ rule: "cluster.backend.configRequired", message: "spec.config must not be empty for an external backend — it needs at least a connection address" });
    }
    // Transport security: reject a plaintext coordinator unless opted out
    // with `spec.config.allow_insecure_transport: true`. Mirrors the gateway
    // boot guard + the operator admission webhook (validators/cluster.rs).
    if (!singleNode && !configEmpty && spec?.config?.allow_insecure_transport !== true) {
        const c = spec.config;
        const lead = (s: any) => (typeof s === "string" ? s.replace(/^\s+/, "") : "");
        let insecure: string | null = null;
        if (backend === "redis" && lead(c?.url).startsWith("redis://")) {
            insecure = "the redis `url` uses the plaintext `redis://` scheme (use `rediss://`)";
        } else if (backend === "consul" && lead(c?.address).startsWith("http://")) {
            insecure = "the consul `address` uses the plaintext `http://` scheme (use `https://`)";
        } else if (backend === "etcd" && Array.isArray(c?.endpoints) &&
                   c.endpoints.some((e: any) => !lead(e).startsWith("https://"))) {
            insecure = "an etcd `endpoint` is not an `https://` URL (use `https://`)";
        } else if (backend === "nats" && c?.tls?.require_tls === false) {
            insecure = "nats `tls.require_tls` is set to `false` (plaintext)";
        }
        if (insecure) {
            f.push({ rule: "cluster.transport.insecure", message: `spec.config: ${insecure}. Set spec.config.allow_insecure_transport: true to accept plaintext (local/dev only).` });
        }
    }
    const seen = new Set<string>();
    const refs: any[] = spec?.credentialRefs ?? [];
    refs.forEach((c, i) => {
        if (blank(c?.name)) {
            f.push({ rule: "cluster.credentialRefs.name", message: `spec.credentialRefs[${i}].name must not be empty` });
            return;
        }
        if (blank(c?.secretName)) {
            f.push({ rule: "cluster.credentialRefs.secretName", message: `spec.credentialRefs[${i}].secretName must not be empty` });
        }
        if (seen.has(c.name)) {
            f.push({ rule: "cluster.credentialRefs.uniqueName", message: `spec.credentialRefs name '${c.name}' is duplicated` });
        }
        seen.add(c.name);
    });
    return f;
}

/** Mirrors the MCPGRoute admission rules (validators/route.rs). Tenant-unset is
 * an admit-with-warning in the webhook, so it is NOT a reject here. */
export function validateRouteSpec(spec: any): Finding[] {
    const f: Finding[] = [];
    if (blank(spec?.gatewayRef?.name)) f.push({ rule: "route.gatewayRef.name", message: "spec.gatewayRef.name must not be empty" });
    const tools: any[] = spec?.match?.tools ?? [];
    if (tools.length === 0) f.push({ rule: "route.match.tools.nonEmpty", message: "spec.match.tools must list at least one tool" });
    const seen = new Set<string>();
    tools.forEach((t, i) => {
        const id = typeof t?.id === "string" ? t.id.trim() : "";
        if (id === "") {
            f.push({ rule: "route.match.tools.id", message: `spec.match.tools[${i}].id must not be empty` });
            return;
        }
        if (seen.has(id)) f.push({ rule: "route.match.tools.uniqueId", message: `spec.match.tools contains duplicate tool id '${id}'` });
        seen.add(id);
    });
    for (const chain of ["identityChain", "policyChain", "auditChain"]) {
        const ids: any[] = spec?.[chain] ?? [];
        ids.forEach((id, i) => {
            if (blank(id)) f.push({ rule: "route.chain.nonEmptyId", message: `spec.${chain}[${i}] must not be empty` });
        });
    }
    return f;
}

/** Mirrors the MCPGTenant admission rules (validators/tenant.rs). */
export function validateTenantSpec(spec: any): Finding[] {
    const f: Finding[] = [];
    const namespaces: any[] = spec?.namespaces ?? [];
    if (namespaces.length === 0) f.push({ rule: "tenant.namespaces.nonEmpty", message: "spec.namespaces must not be empty" });
    const seen = new Set<string>();
    for (const ns of namespaces) {
        if (blank(ns)) {
            f.push({ rule: "tenant.namespaces.nonEmptyEntry", message: "spec.namespaces[] entries must not be empty" });
            continue;
        }
        if (seen.has(ns)) f.push({ rule: "tenant.namespaces.unique", message: `spec.namespaces lists '${ns}' more than once` });
        seen.add(ns);
    }
    (spec?.allowedPlugins ?? []).forEach((a: any, i: number) => {
        const nameSet = !blank(a?.name);
        const prefixSet = !blank(a?.registryPrefix);
        if (!nameSet && !prefixSet) f.push({ rule: "tenant.allowedPlugins.matcher", message: `spec.allowedPlugins[${i}] must set name or registryPrefix` });
    });
    if (spec?.quotas) {
        for (const field of ["maxGateways", "maxPluginSets", "maxRoutes", "maxReplicasPerGateway"]) {
            const v = spec.quotas[field];
            if (typeof v === "number" && v < 0) f.push({ rule: "tenant.quotas.nonNegative", message: `spec.quotas.${field} must be ≥ 0` });
        }
    }
    if (spec?.identityAttribute && blank(spec.identityAttribute.key)) {
        f.push({ rule: "tenant.identityAttribute.key", message: "spec.identityAttribute.key must not be empty when set" });
    }
    return f;
}

/** Mirrors the MCPGPluginMirror admission rules (validators/plugin_mirror.rs). */
export function validatePluginMirrorSpec(spec: any): Finding[] {
    const f: Finding[] = [];
    const svc = spec?.endpoint?.service ?? {};
    if (blank(svc.namespace)) f.push({ rule: "pluginMirror.endpoint.service.namespace", message: "spec.endpoint.service.namespace must not be empty" });
    if (blank(svc.name)) f.push({ rule: "pluginMirror.endpoint.service.name", message: "spec.endpoint.service.name must not be empty" });
    if (!svc.port) f.push({ rule: "pluginMirror.endpoint.service.port", message: "spec.endpoint.service.port must be in 1..=65535" });
    const up = spec?.upstream ?? {};
    if (blank(up.registry)) {
        f.push({ rule: "pluginMirror.upstream.registry", message: "spec.upstream.registry must not be empty" });
    } else if (!up.registry.includes(".") && !up.registry.includes(":")) {
        f.push({ rule: "pluginMirror.upstream.registryHost", message: `spec.upstream.registry '${up.registry}' does not look like a registry host` });
    }
    if (blank(up.namespace)) f.push({ rule: "pluginMirror.upstream.namespace", message: "spec.upstream.namespace must not be empty" });
    if (spec?.auth && blank(spec.auth.secretRef?.secretName)) {
        f.push({ rule: "pluginMirror.auth.secretName", message: "spec.auth.secretRef.secretName must not be empty when auth is set" });
    }
    return f;
}

/** Dispatch by Pulumi resource type token (…:MCPGGateway etc.). */
export function validateByType(type: string, spec: any): Finding[] {
    if (type.endsWith(":MCPGGateway")) return validateGatewaySpec(spec);
    if (type.endsWith(":MCPGPlugin")) return validatePluginSpec(spec);
    if (type.endsWith(":MCPGPluginSet")) return validatePluginSetSpec(spec);
    if (type.endsWith(":MCPGRevocationList")) return validateRevocationListSpec(spec);
    if (type.endsWith(":MCPGCluster")) return validateClusterSpec(spec);
    if (type.endsWith(":MCPGRoute")) return validateRouteSpec(spec);
    if (type.endsWith(":MCPGTenant")) return validateTenantSpec(spec);
    if (type.endsWith(":MCPGPluginMirror")) return validatePluginMirrorSpec(spec);
    return [];
}
