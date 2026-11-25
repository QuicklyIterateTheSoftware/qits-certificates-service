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
  Flyway. Today it holds `CertificateSmoke`.
- `service/`: the deployable. It holds health (`health/CryptoReadiness`), and the REST surface goes
  in `api` when the doors land. Every Quarkus test lives here.

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
- **Every served type** gets listed in a wire-reflection registration (`ApiWireReflection`, as in
  the other services) once the doors land.

## Generated files, and how to regenerate each

| File | Written by |
|---|---|
| `docs/openapi.yml` | `OpenApiSchemaExportTest`. It always rewrites the file, and the diff is the review. |
| `golden-masters/index.json` | Hand-written and empty until the doors land; then the recording test writes it. |

A new door needs a golden master in the same commit. The release gate fails any operation in
`docs/openapi.yml` that `golden-masters/index.json` does not cover.

## The userflow catalogue, and the native proof

`stories/**IT` boot the **packaged** service against `idp.MockIdp`, with the OIDC tenant on. They
write their reports under `service/target/userstories/`, and the java-service release recipe
requires that directory. This module opts into its ITs (`skipITs=false`), so a plain `./mvnw verify`
runs them.

`CertificatesBootstrapIT` is also **the native IT**: it asserts the `certificates-crypto` readiness
check. Under `./mvnw verify -Dnative` that check signs a CSR end to end inside the binary.

The release recipe does not run it natively, because the image build is `package -DskipTests`. In
production the same check is the deploy's health gate, so a native image that has lost part of Bouncy
Castle never becomes ready.
