# qits-certificates-service

The platform's own **certificate authority** (epic qits-2524). Application `qits-certificates`, image
`qits/qits-certificates`, Java package `eu.wohlben.qits.certificates`, archetype SERVICE. Quarkus
native, served at `https://certificates.qits.<domain>/certificates` through the public edge (`exposure: public`, so qits-egress on qits-net can reach the leaf door; every door still checks its caller).

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
| `qits.certificates.leaf.requesters` | `${QITS_ENVIRONMENT:dev}-qits-egress` (comma separated `sub`s) |
| `qits.certificates.workload.validity` | `P1D` (startup fails above `leaf.validity`) |
| `qits.certificates.domain` | `${QITS_DOMAIN:}` (blank refuses no platform host, logged once at WARN) |

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
  `./mvnw verify -Dnative`) and parses the bundle the door serves, and `LeafIssuanceIT` has the same
  process sign a CSR with the anchor's stored key end to end, as `WorkloadCertificateIT` does for a
  workload certificate;
- the deploy's health gate on `/certificates/q/health/ready` refuses a container without one.

## Doors

| Door | Roles | Answer |
|---|---|---|
| `GET /certificates/api/anchors` | `@PermitAll` | The PEM bundle (ACTIVE, then PENDING, then RETIRING) as `text/plain` (the default) or `application/x-pem-file`; with `Accept: application/json`, `{"version","anchors":[{"id","status","subject","serial","notBefore","notAfter","sha256","activatesAt","retiresAt"}]}`. `ETag: "<version>"`, the SHA-256 of the PEM bundle; `If-None-Match` answers 304. 503 while no anchor is loaded. |
| `POST /certificates/api/anchors/rotate` | `qits:admin` | 201 with the new PENDING anchor (the JSON shape above), 409 `{"error","anchorId"}` while one is PENDING. |
| `POST /certificates/api/leaves` | `qits:system`, plus the requester list | Body `{"csr":"<PKCS#10 PEM>"}`: 201 `{"certificate","chain","serial","notAfter","anchorId"}` (the chain is the leaf, then the ACTIVE anchor). 400 `{"error":"name refused","name"}` for a refused name, 400 `{"error":"<reason>"}` for any other CSR fault, 403 `{"error":"not a leaf requester"}`, 503 while no anchor is ACTIVE. See "Leaves" below. |
| `POST /certificates/api/workload-certificates` | `@Authenticated` (any platform bearer) | Body `{"csr":"<PKCS#10 PEM>"}`: 201 `{"certificate","chain","serial","notAfter","anchorId","principal"}`, a client certificate for the caller's own principal. 400 `{"error":"<reason>"}` for a CSR fault, 401 without a bearer, 403 `{"error":"<reason>"}` for a token that may not have one, 503 while no anchor is ACTIVE. See "Workload certificates" below. |

No answer, log line, health check or error body ever carries a `PRIVATE KEY` PEM block
(`NoPrivateKeyTest` calls every door on every path and scans bodies, headers and the log).

Health is at `/certificates/q/health/{live,ready}`, and the API document at
`/certificates/q/openapi` (browsable at `/certificates/q/swagger-ui`).

    curl -s https://certificates.qits.<domain>/certificates/api/anchors \
      | openssl x509 -noout -subject -ext basicConstraints

## Leaves

`control/Leaves` signs, `control/LeafPolicy` decides:

- **Requester.** The door needs `qits:system`, and then the token's `sub` must be in
  `qits.certificates.leaf.requesters`. Anyone else gets 403 `{"error":"not a leaf requester"}`; a
  caller without `qits:system` gets the same 403, mapped on this door only so it is audited too.
- **CSR.** One PKCS#10 PEM (at most 16 KiB) whose signature verifies, over an EC P-256 key or an
  RSA key of at least 2048 bits. Its subject is ignored. Anything else is 400 with the reason.
- **Names.** The subjectAltName of the CSR's extensionRequest: only dNSName, 1 to 10 (duplicates
  folded), lower-cased, each a valid hostname. Refused with 400 `{"error":"name refused","name"}`: a
  wildcard, an IP address, `localhost` (and `*.localhost`), a single label, a name under
  `.internal` or `.local`, and `qits.<QITS_DOMAIN>` or anything under it.
- **The leaf.** Subject `CN=<first name>`; SAN the names; basicConstraints critical CA:false;
  keyUsage critical digitalSignature (+ keyEncipherment for RSA); extendedKeyUsage serverAuth;
  AuthorityKeyIdentifier the ACTIVE anchor's key id; a SubjectKeyIdentifier; `notBefore` now − 5
  min; `notAfter` = min(now + `leaf.validity`, the anchor's `notAfter`); a 128-bit random serial;
  `SHA384withECDSA` by the ACTIVE anchor's key, read from `key.pem` for each leaf.
- **Audit.** One INFO line on the logger `eu.wohlben.qits.certificates.audit` per decision, a
  value that does not apply being `-` and the reason last:

      certificates decision=ISSUED requester=dev-qits-egress names=api.example.org,www.example.org serial=<hex> anchor=<id> notAfter=2026-12-02T12:00:00Z reason=-
      certificates decision=REFUSED requester=dev-qits-ci names=- serial=- anchor=- notAfter=- reason=not a leaf requester

  The reasons are `not a leaf requester`, `not qits:system`, `name refused: <name> is <rule>`, the
  CSR's fault, `no anchor is ACTIVE`, `the ACTIVE anchor has expired`, `the ACTIVE anchor's key
  cannot be read` and `signing failed`. Every caller-supplied value is made printable first; the
  CSR itself is never logged.

## Workload certificates

Epic qits-2626, qits-2756. `api/WorkloadCertificatesResource` decides who, `control/WorkloadCertificates`
signs, `control/WorkloadCrypto` builds the certificate. The key is made in the workload and only its
CSR is sent.

- **Who.** The principal comes from the validated bearer alone, through qits-auth-core's
  `WorkloadPrincipal` (the grammar qits-egress keys its grants with): `application:<app>` for a
  service client `<env>-<app>` holding `qits:system` and `clients/<sub>`, else `agent:<agent>` (with
  its `project`), else `project:<project>`. Opaque `qits_tok_` callers arrive as the JWT the edge
  introspected them into. The CSR's subject and subjectAltNames are never read.
- **Refused with 403**, reason as the error: `an exchanged token` (`act`), `a person's token`
  (`credential_type`), `no workload principal` (it maps to `subject:`, or the identity is not a
  JWT), `a name unfit for a certificate` (a foreign environment's service client, whose `project`
  is `*`, for one).
- **CSR.** Checked like a leaf's (PKCS#10, at most 16 KiB, signature verifies, EC P-256 or RSA of
  at least 2048 bits); 400 with the reason otherwise.
- **The certificate.** Subject `CN=<kind>:<name>` (informational, cut at 64, never read); URI SAN
  `urn:qits:principal:<kind>:<name>`, plus `urn:qits:project:<id>` for an agent; an application also
  gets DNS SAN `<QITS_ENVIRONMENT>-<app>`, its wire alias. basicConstraints critical CA:false;
  keyUsage critical digitalSignature (+ keyEncipherment for RSA); EKU clientAuth, + serverAuth for an
  application. `notBefore` now − 5 min, `notAfter` = min(now + `workload.validity`, the anchor's
  `notAfter`). No revocation: deleting a token or rotating a client stops its renewals, so a
  principal's tail is at most one validity.
- **Audit.** The leaves' line with `kind=workload principal=<p>`, for every issue and refusal (the
  401 included); `names` are the URIs and DNS names the certificate carries, never the CSR's:

      certificates decision=ISSUED kind=workload requester=dev-qits-edge principal=application:qits-edge names=urn:qits:principal:application:qits-edge,dev-qits-edge serial=<hex> anchor=<id> notAfter=2026-11-26T12:00:00Z reason=-
      certificates decision=REFUSED kind=workload requester=<sub> principal=subject:<sub> names=- serial=- anchor=- notAfter=- reason=a person's token

## Contracts

The provider golden masters under `golden-masters/` (published as
`eu.wohlben.qits:qits-certificates-golden-masters`) are recorded by
`contracts/GoldenMasterRecordingTest` in eight states, all staged from the fixed fixture anchors in
`service/src/test/resources/fixtures/` with the clock pinned, so they re-record byte for byte:
`one ACTIVE anchor` and `one ACTIVE and one PENDING anchor` for the anchors doors, and `leaf
issued`, `leaf name refused` and `not a leaf requester` for `issueLeaf`, and `workload certificate issued`
(qits-edge's service token), `workload certificate refused` (a person's token) and `workload csr
refused` for `issueWorkloadCertificate`. The leaf and workload states send a
fixed fixture CSR (`fixtures/csr/`) as the requester or as a `qits:system` service that is not one,
and pin the leaf's randomness (`support/TestEntropy`), so the issued leaf, serial and signature
included, is the same bytes on every run. `ConsumerPactVerificationTest` verifies the
consumers' pacts against the same states (none pinned yet: qits-2632's trust-anchors client is the
first).

## Build

    ./mvnw verify            # domain + service, the packaged story included
    ./mvnw verify -Dnative   # the same story against the native binary (needs GraalVM 25)

A clone of this repository builds alone. The qits-* jars come from the platform Maven repository
(`<repositories>` in the root pom).
