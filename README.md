# @mcpg/pulumi-policy

A Pulumi **CrossGuard** policy pack that enforces the MCPG Kubernetes operator's
admission rules at `pulumi preview`, before anything reaches a cluster. It
inspects the `mcpg.dev` custom resources a program declares — gateways,
plugins, plugin sets, revocation lists, clusters, routes, tenants and plugin
mirrors — and reports the violations the operator's admission webhook would
return, locally and with no API-server round trip.

## Quick start

The pack is referenced at preview/update time rather than imported into your
program:

```bash
npm i --save-dev @mcpg/pulumi-policy
pulumi preview --policy-pack node_modules/@mcpg/pulumi-policy
```

A violation is printed as `[<rule-id>] <message>` — for example
`[gateway.workloadIdentity.oneOf] workloadIdentity must be exactly one of
aws|gcp|azure|spiffe`. The rule id is stable, and is the same identifier the
MCPG Terraform provider's plan-time validators emit.

`main` points at `bin/index.js`, so a source checkout has to be compiled before
Pulumi can load it:

```bash
npm install && npm run build   # tsc → bin/
```

## Rules

| Kind | What it checks |
|---|---|
| `MCPGGateway` | `spec.image` present; `replicas` ≥ 1 when set; at most one of `workloadIdentity.{aws,gcp,azure,spiffe}`; a present `ingress` block carries a non-empty `ingressClassName`, at least one host, and non-empty `paths` per host. |
| `MCPGPlugin` | `pluginId` non-empty and reverse-DNS; `version` non-empty; `pluginClass` is a known plugin class; `oci.image` carries a registry component and a tag or digest; the artifact is digest-pinned **or** carries a cosign identity; `trust.signingKeyRef.secretName` present (Ed25519 signing is the mandatory baseline); a cosign block has a non-empty, anchored `certificateIdentityRegexp` and an `oidcIssuer`; an SLSA block sets `configMapName`, `sourceUri` and `sourceTag`. |
| `MCPGPluginSet` | `entries` non-empty; each entry has a reverse-DNS `id` and a `pluginRef.name`; ids unique; `capabilityGrants` keys name a declared entry and grant a non-empty capability list. |
| `MCPGRevocationList` | `version == 1`; every `artifactSha256` is 64 hex characters; every revocation carries a `reason`; no duplicate hashes. |
| `MCPGCluster` | the `single_node` backend takes no `config`; every other backend requires one; a plaintext coordinator address (`redis://`, `http://` Consul, non-`https://` etcd endpoints, NATS with `tls.require_tls: false`) is rejected unless `config.allow_insecure_transport: true`; `credentialRefs` entries carry `name` + `secretName` and unique names. |
| `MCPGRoute` | `gatewayRef.name` non-empty; `match.tools` lists at least one tool; tool ids non-empty and unique; no empty entry in `identityChain` / `policyChain` / `auditChain`. |
| `MCPGTenant` | `namespaces` non-empty, with entries non-empty and unique; each `allowedPlugins` entry sets `name` or `registryPrefix`; quota fields are non-negative; `identityAttribute.key` non-empty when that block is set. |
| `MCPGPluginMirror` | `endpoint.service.{namespace,name,port}` set; `upstream.registry` present and shaped like a registry host; `upstream.namespace` present; `auth.secretRef.secretName` present when `auth` is set. |

Two behaviours exist specifically so the preview verdict matches the cluster's:

- A `certificateIdentityRegexp` using lookahead, lookbehind or a back-reference
  is rejected even though JavaScript would compile it, because the operator
  compiles the pattern with an RE2-style engine that will not.
- SHA-256 hashes are accepted in either case, and duplicate detection is
  case-insensitive, matching the operator's lowercase-then-deduplicate
  behaviour.

Cross-resource and client-backed admission checks are deliberately **not**
mirrored: the per-tenant replica cap and plugin allowlist need cluster state,
and `image.tag` is filled in by the mutating webhook, so enforcing it at preview
would false-reject a program that relies on defaulting. Treat the pack as a
high-coverage local gate, not a guarantee of admission acceptance.

## Validator library

The rules live in [`src/validators.ts`](src/validators.ts) as pure functions
with no Pulumi runtime dependency, which is what lets the same logic back both
the policy pack and a cross-tool contract test:

- `validateByType(type, spec)` — dispatch by Pulumi type token.
- `validateGatewaySpec`, `validatePluginSpec`, `validatePluginSetSpec`,
  `validateRevocationListSpec`, `validateClusterSpec`, `validateRouteSpec`,
  `validateTenantSpec`, `validatePluginMirrorSpec` — one per kind, each
  returning `Finding[]` (`{ rule, message }`); an empty array means accept.
- `isSha256Hex`, `isAnchoredRegexp`, `countWorkloadIdentities`,
  `findDuplicates` — the shared predicates.

The MCPG Terraform provider ships a Go port of these same functions, and a
shared fixture corpus asserts both sides return identical verdicts, so a rule
relaxed on one side fails the build.

## Configuration

The pack takes no configuration. It registers one policy,
`mcpg-admission-mirror`, declared at `enforcementLevel: "mandatory"`, so a
violation blocks the update instead of emitting an advisory.

Resources are dispatched on the Pulumi type-token suffix (`…:MCPGGateway`,
`…:MCPGPlugin`, …) and read from `props.spec`. Any resource whose token matches
no rule set yields no findings, so the pack is safe to apply across a whole
stack.

## Build and test

```bash
npm run build                       # tsc → bin/
node --test bin/validators.test.js  # unit tests over the pure validators
```

Inside the MCPG workspace, from the repo root:

```bash
pnpm --filter ./iac/pulumi/policy exec tsc -b --noEmit   # tsc --noEmit
pnpm --filter ./iac/pulumi/policy test        # builds, then runs the validator tests
```

## Licence

Apache-2.0.

## See also

- <https://mcpg.dev/docs/self-hosting/pulumi> — installing MCPG with Pulumi,
  including the `@mcpg/pulumi` components and the `@mcpg/pulumi-crds` typed SDK
  this pack guards.
- <https://mcpg.dev/docs/reference/operator-crds> — the `mcpg.dev` CRDs and the
  admission rules being mirrored.
- <https://mcpg.dev/docs/security/plugin-security> — signing, trust roots and
  revocation, which the plugin and revocation-list rules enforce.
- <https://mcpg.dev/docs/self-hosting/terraform-provider> — the same rules
  enforced as Terraform plan-time validation.
