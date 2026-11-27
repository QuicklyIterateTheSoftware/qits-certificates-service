# qits-certificates — working notes

Read `README.md` first: it describes what this service is. This file holds the conventions on top of
it. Add to it as the code grows.

## The rule that shapes everything

**A clone of this repo alone builds and tests green.** That means no monorepo, no docker and no
earlier `mvn install` somewhere else. `./mvnw verify` is the gate. There is no database, so no store
needs starting. **Never use Testcontainers or a Quarkus dev service.**

The one exception is the platform Maven repository (`<repositories>` in the root pom), where the
qits-* jars live. Their versions are pinned exactly in the root pom. qits-maintenance's bumps move
them; never move them by hand.

## Layout

- `domain/`: the certificate authority (`control`). It has no web stack, no datasource and no
  Flyway. `Anchors` is the state machine and the published bundle, `AnchorStore` the volume
  (`<ca-dir>/anchors/<id>/`), `AnchorCrypto` the keys and certificates. `Leaves` signs leaves and
  writes the audit line, `LeafPolicy` holds every rule of who may ask and for which names, and
  `LeafCrypto` builds the leaf. `WorkloadCertificates` and `WorkloadCrypto` sign workload client
  certificates for a `WorkloadRequest` the door decided from the bearer (qits-2756); they reuse
  `LeafPolicy.key` for the CSR and never read its names. Its tests are plain JUnit on a temp directory with a clock they
  move (`AnchorsTest`, `LeavesTest`, `LeafPolicyTest`).
- `service/`: the deployable. `api` (the doors, `Roles`, `AnchorsWire`, `LeavesWire`,
  `ApiWireReflection`), `health/AnchorsReadiness`, and `rotation` (the startup run and the daily
  `@Scheduled` job, and the `Clock` and `Entropy` producers). Every Quarkus test lives here.

## Conventions

- **Never print key material.** No answer, log line, health check or error body may carry a
  `PRIVATE KEY` PEM block. The tests assert this on every body they read; every new door does the
  same.
- **Use the JDK for crypto and Bouncy Castle for structures.** Keys come from `KeyPairGenerator` and
  signatures are SunEC's. bcpkix builds and parses certificates, CSRs and PEM. Do not register BC as
  a JCA provider unless a native build proves that it is needed. If it is, copy qits-edge's setup:
  `quarkus-security` plus `quarkus.security.security-providers=BC`, with bcprov as a direct
  dependency (it already is one).
- **Write a file on the volume by writing a temp file and `rename()`-ing it into place.** The
  service never deletes a directory it cannot read: it logs it at ERROR and skips it.
- **Roles** are spelled out in each `@RolesAllowed`. Wherever `qits:admin-agent` is admitted,
  `qits:desk-admin` is admitted too (`DeskAdminParityTest`).
- **Every served type** is listed in `api/ApiWireReflection`; `ApiWireReflectionTest` fails on a
  nested type of `AnchorsWire`, `LeavesWire` or `WorkloadsWire` left out.
- **A door that decides from claims** (the workload door) is tested with
  `support/ContractCallers.token(claims, roles)`, whose principal is a `JsonWebToken` as quarkus-oidc
  leaves it; `caller(sub, roles)` is a bare principal with roles.
- **Every leaf decision is audited**, one INFO line on `eu.wohlben.qits.certificates.audit`
  (README, "Leaves"). A new refusal path writes its line through `Leaves`; a door-level refusal
  (the 403 for a caller without `qits:system`) is mapped on `LeavesResource` for that reason.
- **No `SecureRandom` in a static field**, nor in anything built at image-build time (a
  `KeyPairGenerator` holds one): the native image refuses it in its heap. Make one per call. A leaf
  takes its one from the `Entropy` bean (`SecureRandom::new` in the service), which the suite's
  `support/TestEntropy` pins so a recorded leaf is the same bytes every run.
- **Time is the injected `java.time.Clock`.** The service produces the system clock as a
  `@DefaultBean`; the suite's `support/TestClock` replaces it, and `support/Ca` stages the volume
  (empty, a fresh boot, or the fixture anchors with the clock pinned). The daily job is off in
  `%test` (`quarkus.scheduler.enabled=false`); tests call `Anchors.tick()` themselves.

## Generated files, and how to regenerate each

| File | Written by |
|---|---|
| `docs/openapi.yml` | `OpenApiSchemaExportTest`. It always rewrites the file, and the diff is the review. |
| `golden-masters/**` | `contracts/GoldenMasterRecordingTest`. It compares by default; `-Dgolden.update=true` rewrites. |
| `service/src/test/resources/fixtures/anchors/**` | Made ONCE by the service's own `AnchorCrypto` and committed: the golden masters' bytes depend on them. Never regenerate them casually. |

A new door needs a golden master in the same commit. The recordings call with `Accept:
application/json`, as the state's caller (`ProviderStates.Setup#caller`, which pact verification
uses too); a random value a door makes (a new anchor's `serial` and `sha256`) is frozen as a
unique token, a leaf's randomness is pinned instead (`TestEntropy`), and everything else comes from
the fixture anchors and the fixture CSRs (`fixtures/csr/`, made once with openssl, never
regenerated casually), so a re-record is byte-identical. The release gate fails any operation in
`docs/openapi.yml` that `golden-masters/index.json` does not cover.

## The userflow catalogue, and the native proof

`stories/**IT` boot the **packaged** service against `idp.MockIdp`, with the OIDC tenant on. They
write their reports under `service/target/userstories/`, and the java-service release recipe
requires that directory. This module opts into its ITs (`skipITs=false`), so a plain `./mvnw verify`
runs them.

`CertificatesBootstrapIT` is also **the native IT**: the packaged process boots on an empty CA
volume (a temp directory), makes its first anchor with bcpkix inside the binary under
`./mvnw verify -Dnative`, reports `certificates-anchors` UP, and serves the bundle the story parses.
`stories/leaves/LeafIssuanceIT`, on the same profile, has that process sign a CSR with the
anchor's stored key end to end and refuse a non-requester and an agent. `stories/workloads/WorkloadCertificateIT`
has it validate a real token, map it through `WorkloadPrincipal` and sign a workload certificate
(qits-2756), and refuse a person's and an exchanged token.

The release recipe does not run it natively, because the image build is `package -DskipTests`. In
production the same check is the deploy's health gate, so a native image that has lost part of Bouncy
Castle never becomes ready.
