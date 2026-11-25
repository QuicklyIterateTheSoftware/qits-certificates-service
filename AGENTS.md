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
  (`<ca-dir>/anchors/<id>/`), `AnchorCrypto` the keys and certificates. Its tests are plain JUnit
  on a temp directory with a clock they move (`AnchorsTest`).
- `service/`: the deployable. `api` (the doors, `Roles`, `AnchorsWire`, `ApiWireReflection`),
  `health/AnchorsReadiness`, and `rotation` (the startup run and the daily `@Scheduled` job, and the
  `Clock` producer). Every Quarkus test lives here.

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
  nested type of `AnchorsWire` left out.
- **No `SecureRandom` in a static field**, nor in anything built at image-build time (a
  `KeyPairGenerator` holds one): the native image refuses it in its heap. Make one per call.
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
application/json`; a random value a door makes (a new anchor's `serial` and `sha256`) is frozen as a
unique token, and everything else comes from the fixture anchors, so a re-record is byte-identical. The release gate fails any operation in
`docs/openapi.yml` that `golden-masters/index.json` does not cover.

## The userflow catalogue, and the native proof

`stories/**IT` boot the **packaged** service against `idp.MockIdp`, with the OIDC tenant on. They
write their reports under `service/target/userstories/`, and the java-service release recipe
requires that directory. This module opts into its ITs (`skipITs=false`), so a plain `./mvnw verify`
runs them.

`CertificatesBootstrapIT` is also **the native IT**: the packaged process boots on an empty CA
volume (a temp directory), makes its first anchor with bcpkix inside the binary under
`./mvnw verify -Dnative`, reports `certificates-anchors` UP, and serves the bundle the story parses.
Signing a CSR end to end returns to it with the leaves door (qits-2524 C3).

The release recipe does not run it natively, because the image build is `package -DskipTests`. In
production the same check is the deploy's health gate, so a native image that has lost part of Bouncy
Castle never becomes ready.
