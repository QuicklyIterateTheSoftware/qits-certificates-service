package eu.wohlben.qits.certificates.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Signing a workload certificate with the ACTIVE anchor of a temp volume (qits-2756). */
class WorkloadCertificatesTest {

  static final Instant T0 = Instant.parse("2026-11-27T10:00:00Z");

  static final String CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

  static final String SERVER_AUTH = "1.3.6.1.5.5.7.3.1";

  static final WorkloadRequest AGENT =
      new WorkloadRequest(
          "tok-workspace-agent-x",
          "agent:6fe232fc-0000-4000-8000-000000000001",
          List.of(
              "urn:qits:principal:agent:6fe232fc-0000-4000-8000-000000000001",
              "urn:qits:project:8273c743-e0bb-4d93-90d4-391aa10d9151"),
          List.of());

  static final WorkloadRequest EDGE =
      new WorkloadRequest(
          "dev-qits-edge",
          "application:qits-edge",
          List.of("urn:qits:principal:application:qits-edge"),
          List.of("dev-qits-edge"));

  @TempDir Path ca;

  MutableClock clock;

  Anchors anchors;

  WorkloadCertificates workloads;

  @BeforeEach
  void boot() {
    clock = new MutableClock(T0);
    anchors = new Anchors(ca, AnchorPolicy.defaults("dev"), clock);
    workloads = workloads(Duration.ofDays(1));
  }

  private WorkloadCertificates workloads(Duration validity) {
    return new WorkloadCertificates(anchors, validity, Duration.ofDays(7), clock, SecureRandom::new);
  }

  @Test
  void anAgentGetsAClientCertificateNamingItAndItsProject() throws Exception {
    anchors.start();
    Anchor active = anchors.bundle().anchors().get(0);

    WorkloadCertificates.Workload issued = workloads.issue(AGENT, Csrs.forNames("ignored.example.org"));

    X509Certificate certificate = issued.certificate();
    certificate.verify(active.certificate().getPublicKey());
    assertEquals(
        List.of(
            List.of(6, "urn:qits:principal:agent:6fe232fc-0000-4000-8000-000000000001"),
            List.of(6, "urn:qits:project:8273c743-e0bb-4d93-90d4-391aa10d9151")),
        certificate.getSubjectAlternativeNames().stream().toList(),
        "the names asked for in the CSR never reach the certificate");
    assertEquals(
        "CN=agent:6fe232fc-0000-4000-8000-000000000001",
        certificate.getSubjectX500Principal().getName());
    assertEquals(List.of(CLIENT_AUTH), certificate.getExtendedKeyUsage());
    assertEquals(-1, certificate.getBasicConstraints(), "CA:false");
    assertTrue(certificate.getCriticalExtensionOIDs().contains(Extension.keyUsage.getId()));
    assertTrue(certificate.getKeyUsage()[0], "digitalSignature");
    assertFalse(certificate.getKeyUsage()[5], "no keyCertSign");
    assertEquals(T0.minus(Duration.ofMinutes(5)), certificate.getNotBefore().toInstant());
    assertEquals(T0.plus(Duration.ofDays(1)), issued.notAfter(), "one day");
    assertEquals("agent:6fe232fc-0000-4000-8000-000000000001", issued.principal());
    assertEquals(active.id(), issued.anchorId());
    assertEquals(certificate.getSerialNumber().toString(16), issued.serial());

    List<X509Certificate> chain =
        CertificateFactory.getInstance("X.509")
            .generateCertificates(
                new ByteArrayInputStream(issued.chainPem().getBytes(StandardCharsets.US_ASCII)))
            .stream()
            .map(X509Certificate.class::cast)
            .toList();
    assertEquals(List.of(certificate, active.certificate()), chain);
  }

  @Test
  void anApplicationAlsoGetsItsWireAliasAndServerAuth() throws Exception {
    anchors.start();
    X509Certificate certificate =
        workloads.issue(EDGE, Csrs.forNames("api.example.org")).certificate();
    assertEquals(
        List.of(List.of(6, "urn:qits:principal:application:qits-edge"), List.of(2, "dev-qits-edge")),
        certificate.getSubjectAlternativeNames().stream().toList());
    assertEquals(List.of(CLIENT_AUTH, SERVER_AUTH), certificate.getExtendedKeyUsage());
  }

  @Test
  void anRsaKeyGetsKeyEncipherment() throws Exception {
    anchors.start();
    X509Certificate certificate =
        workloads
            .issue(EDGE, Csrs.pem(Csrs.request(Csrs.rsa(2048), Csrs.dns("x.example.org"))))
            .certificate();
    assertTrue(certificate.getKeyUsage()[2], "keyEncipherment");
  }

  @Test
  void aLongPrincipalIsCutInTheCnButNotInTheUri() throws Exception {
    anchors.start();
    String name = "a".repeat(100);
    WorkloadRequest request =
        new WorkloadRequest(
            "tok-y", "project:" + name, List.of("urn:qits:principal:project:" + name), List.of());
    X509Certificate certificate = workloads.issue(request, Csrs.forNames("x.example.org")).certificate();
    assertEquals(
        "CN=" + ("project:" + name).substring(0, 64), certificate.getSubjectX500Principal().getName());
    assertEquals(
        List.of(List.of(6, "urn:qits:principal:project:" + name)),
        certificate.getSubjectAlternativeNames().stream().toList());
  }

  @Test
  void theValidityIsCappedByTheAnchor() throws Exception {
    anchors.start();
    Anchor active = anchors.bundle().anchors().get(0);
    clock.set(active.notAfter().minus(Duration.ofHours(2)));
    assertEquals(active.notAfter(), workloads.issue(AGENT, Csrs.forNames("x.example.org")).notAfter());
  }

  @Test
  void aValidityLongerThanTheLeavesIsRefusedAtStartup() {
    IllegalStateException refused =
        assertThrows(IllegalStateException.class, () -> workloads(Duration.ofDays(8)));
    assertTrue(refused.getMessage().contains("exceeds qits.certificates.leaf.validity"));
    assertThrows(IllegalStateException.class, () -> workloads(Duration.ZERO));
    workloads(Duration.ofDays(7));
  }

  @Test
  void aBadCsrIsRefusedAsACsr() throws Exception {
    anchors.start();
    LeafRefused refused =
        assertThrows(LeafRefused.class, () -> workloads.issue(AGENT, "not a csr"));
    assertEquals(LeafRefused.Kind.CSR, refused.kind());
    assertEquals("the csr is not a PKCS#10 PEM", refused.reason());
    LeafRefused tampered =
        assertThrows(
            LeafRefused.class,
            () ->
                workloads.issue(
                    AGENT,
                    Csrs.pem(Csrs.tampered(Csrs.request(Csrs.ec("secp256r1"), Csrs.dns("x.example.org"))))));
    assertEquals("the csr's signature does not verify", tampered.reason());
    LeafRefused curve =
        assertThrows(
            LeafRefused.class,
            () -> workloads.issue(AGENT, Csrs.pem(Csrs.request(Csrs.ec("secp384r1"), Csrs.dns("x.example.org")))));
    assertEquals(LeafRefused.Kind.CSR, curve.kind());
  }

  @Test
  void aCsrWithoutNamesIsTaken() throws Exception {
    anchors.start();
    workloads.issue(
        AGENT, Csrs.pem(Csrs.request(Csrs.ec("secp256r1"), (org.bouncycastle.asn1.x509.GeneralName[]) null)));
  }

  @Test
  void withoutAnActiveAnchorNothingIsSigned() throws Exception {
    assertThrows(NoActiveAnchor.class, () -> workloads.issue(AGENT, Csrs.forNames("x.example.org")));
  }
}
