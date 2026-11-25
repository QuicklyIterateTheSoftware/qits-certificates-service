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

### The volume

    /work/ca/                         0700, uid 1001 (docker/Dockerfile)
      anchors/                        0700
        <anchorId>/                   0700, one per anchor; the id is a UUID
          cert.pem                    0644, the self-signed CA certificate
          key.pem                     0600, the private key, PKCS#8 (deleted once RETIRED)
          state.json                  {"id","status","createdAt","activatesAt","retiresAt","notAfter","sha256"}
        .new-<anchorId>/              a new anchor being assembled; renamed into place whole

Every file is written to a temp file beside it and renamed into place, so a crash leaves the old
file or the new one. At startup every directory is read; one with a malformed `state.json`, a
certificate whose SHA-256 is not the state's, or a key that is missing or not the certificate's is
logged at ERROR and **ignored, never deleted**.

## Anchors

EC P-384, signed `SHA384withECDSA`, subject `CN=qits platform CA <QITS_ENVIRONMENT> <yyyy-MM>,
O=qits`, a 128-bit random serial, `basicConstraints` critical CA:true pathLen 0, `keyUsage` critical
keyCertSign + cRLSign, and a SubjectKeyIdentifier.

| Status | In the bundle | Signs leaves |
|---|---|---|
| PENDING | yes | no |
| ACTIVE | yes, first | yes (exactly one) |
| RETIRING | yes | no |
| RETIRED | no | no (`key.pem` deleted, `cert.pem` kept) |

### Rotation

`rotation/AnchorRotation` runs `control/Anchors.tick()` once at startup and then every 24 hours
(`@Scheduled(every = "24h")`):

1. **First boot** (no anchor): one ACTIVE anchor is made at once. (No ACTIVE anchor but a PENDING
   one, which only a crash mid-activation leaves, promotes the PENDING one.)
2. **Activation**: a PENDING anchor whose `activatesAt` has passed becomes ACTIVE; the previous
   ACTIVE one becomes RETIRING with `retiresAt = now + leaf validity + P1D`.
3. **Retirement**: a RETIRING anchor whose `retiresAt` has passed becomes RETIRED, and its
   `key.pem` is deleted.
4. **Renewal**: when the ACTIVE anchor's `notAfter` is less than `renew-before` away and no anchor
   is PENDING, a PENDING one is made with `activatesAt = now + overlap`.

`POST /certificates/api/anchors/rotate` starts step 4 by hand. A container picks the bundle up only
when it is created: the overlap is the window in which every new container learns the next anchor
before it signs anything.

### Configuration

| Key | Default |
|---|---|
| `qits.certificates.ca-dir` | `/work/ca` |
| `qits.certificates.environment` | `${QITS_ENVIRONMENT:dev}` |
| `qits.certificates.anchor.validity` | `P1826D` |
| `qits.certificates.anchor.overlap` | `P30D` |
| `qits.certificates.anchor.renew-before` | `P365D` |
| `qits.certificates.leaf.validity` | `P7D` |

## Crypto

Keys and signatures use the JDK's default provider (SunEC); `key.pem` is PKCS#8 written and read by
the JDK. Bouncy Castle's **bcpkix** (with bcprov beside it, both at the Quarkus BOM's version) builds
and parses the certificates: `JcaX509v3CertificateBuilder`, `PEMParser`, `JcaPEMWriter`. BC is
**not** registered as a JCA provider. Nothing holds a `SecureRandom` in a static field or in anything
initialised at build time: the native image refuses one in its image heap.

The known risk is Bouncy Castle in the native image. The first boot makes the first anchor in the
running process, and the readiness check `certificates-anchors` is DOWN until exactly one ACTIVE
anchor is loaded and its key reads back, so:

- `CertificatesBootstrapIT` asserts it against the packaged artifact (the binary under
  `./mvnw verify -Dnative`) and parses the bundle the door serves;
- the deploy's health gate on `/certificates/q/health/ready` refuses a container without one.

## Doors

| Door | Roles | Answer |
|---|---|---|
| `GET /certificates/api/anchors` | `@PermitAll` | The PEM bundle (ACTIVE, then PENDING, then RETIRING) as `text/plain` (the default) or `application/x-pem-file`; with `Accept: application/json`, `{"version","anchors":[{"id","status","subject","serial","notBefore","notAfter","sha256","activatesAt","retiresAt"}]}`. `ETag: "<version>"`, the SHA-256 of the PEM bundle; `If-None-Match` answers 304. 503 while no anchor is loaded. |
| `POST /certificates/api/anchors/rotate` | `qits:admin` | 201 with the new PENDING anchor (the JSON shape above), 409 `{"error","anchorId"}` while one is PENDING. |
| `POST /certificates/api/leaves` | `qits:system`, plus the requester list | Not yet (qits-2524 C3). |

No answer, log line, health check or error body ever carries a `PRIVATE KEY` PEM block
(`NoPrivateKeyTest` calls every door on every path and scans bodies, headers and the log).

Health is at `/certificates/q/health/{live,ready}`, and the API document at
`/certificates/q/openapi` (browsable at `/certificates/q/swagger-ui`).

    curl -s https://certificates.qits.<domain>/certificates/api/anchors \
      | openssl x509 -noout -subject -ext basicConstraints

## Contracts

The provider golden masters under `golden-masters/` (published as
`eu.wohlben.qits:qits-certificates-golden-masters`) are recorded by
`contracts/GoldenMasterRecordingTest` in two states, `one ACTIVE anchor` and `one ACTIVE and one
PENDING anchor`, both staged from the fixed fixture anchors in `service/src/test/resources/fixtures/`
with the clock pinned, so they re-record byte for byte. `ConsumerPactVerificationTest` verifies the
consumers' pacts against the same states (none pinned yet: qits-2632's trust-anchors client is the
first).

## Build

    ./mvnw verify            # domain + service, the packaged story included
    ./mvnw verify -Dnative   # the same story against the native binary (needs GraalVM 25)

A clone of this repository builds alone. The qits-* jars come from the platform Maven repository
(`<repositories>` in the root pom).
