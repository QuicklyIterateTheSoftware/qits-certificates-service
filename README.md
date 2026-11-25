# qits-certificates-service

The platform's own **certificate authority** (epic qits-2524). Application `qits-certificates`, image
`qits/qits-certificates`, Java package `eu.wohlben.qits.certificates`, archetype SERVICE. Quarkus
native, served at `https://certificates.qits.<domain>/certificates`, behind the private edge only.

It keeps the platform's trust anchors and signs short-lived leaf certificates for the platform
callers allowed to ask for one (qits-egress first). Other containers trust the anchors it publishes.

## What it holds, and where

**There is no database.** The only store is the private volume `qits-certificates-ca`, mounted at
`/work/ca`. `docker/Dockerfile` creates that directory owned by uid 1001 with mode 0700, so a new
volume starts out the same. The volume has one writer, which is why the deployment is
`update_order: stop-first` with one replica.

Each anchor is one directory, `/work/ca/anchors/<anchorId>/`, holding `cert.pem`, `key.pem` (PKCS#8,
0600) and `state.json`. Anchors are EC P-384, signed `SHA384withECDSA`, and move through PENDING,
ACTIVE, RETIRING and RETIRED. The design (rotation, the leaf policy, the audit line) is the dossier
page "Certificates service design" on qits-2524.

## Crypto

Keys and signatures use the JDK's default provider (SunEC). Bouncy Castle's **bcpkix** (with bcprov
beside it, both at the Quarkus BOM's version) builds and parses the structures:
`JcaX509v3CertificateBuilder`, `JcaPKCS10CertificationRequest`, `PEMParser`, `JcaPEMWriter`. BC is
**not** registered as a JCA provider.

The known risk is Bouncy Castle in the native image. `control/CertificateSmoke` runs the whole path
once at startup: it makes an anchor, self-signs it, and signs a CSR end to end. The readiness check
`certificates-crypto` reports the result, so:

- `CertificatesBootstrapIT` asserts it against the packaged artifact, which is the binary under
  `./mvnw verify -Dnative`;
- the deploy's health gate on `/certificates/q/health/ready` refuses a container whose crypto is
  broken.

## Doors

None yet. They come with the CA:

| Door | Roles |
|---|---|
| `GET /certificates/api/anchors` | `@PermitAll`. The PEM bundle, or JSON with an `ETag`. |
| `POST /certificates/api/leaves` | `qits:system`, plus the requester list |
| `POST /certificates/api/anchors/rotate` | `qits:admin` |

Health is at `/certificates/q/health/{live,ready}`, and the API document at
`/certificates/q/openapi` (browsable at `/certificates/q/swagger-ui`).

## Build

    ./mvnw verify            # domain + service, the packaged story included
    ./mvnw verify -Dnative   # the same story against the native binary (needs GraalVM 25)

A clone of this repository builds alone. The qits-* jars come from the platform Maven repository
(`<repositories>` in the root pom).
