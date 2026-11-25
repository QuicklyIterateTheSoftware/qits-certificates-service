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
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Signing a leaf with the ACTIVE anchor of a temp volume. */
class LeavesTest {

  static final Instant T0 = Instant.parse("2026-11-25T10:00:00Z");

  @TempDir Path ca;

  MutableClock clock;

  Anchors anchors;

  Leaves leaves;

  @BeforeEach
  void boot() {
    clock = new MutableClock(T0);
    anchors = new Anchors(ca, AnchorPolicy.defaults("dev"), clock);
    leaves = leaves(anchors);
  }

  private Leaves leaves(Anchors on) {
    return new Leaves(
        on,
        new LeafPolicy(List.of("dev-qits-egress"), "wohlben.eu", Duration.ofDays(7)),
        clock,
        SecureRandom::new);
  }

  static byte[] extension(X509Certificate certificate, org.bouncycastle.asn1.ASN1ObjectIdentifier id) {
    return ASN1OctetString.getInstance(certificate.getExtensionValue(id.getId())).getOctets();
  }

  @Test
  void theLeafIsSignedByTheActiveAnchorForTheNamesAsked() throws Exception {
    anchors.start();
    Anchor active = anchors.bundle().anchors().get(0);

    Leaves.Leaf leaf =
        leaves.issue("dev-qits-egress", Csrs.forNames("api.example.org", "www.example.org"));

    X509Certificate certificate = leaf.certificate();
    certificate.verify(active.certificate().getPublicKey());
    assertEquals(active.certificate().getSubjectX500Principal(), certificate.getIssuerX500Principal());
    assertEquals("CN=api.example.org", certificate.getSubjectX500Principal().getName());
    assertEquals(
        List.of(List.of(2, "api.example.org"), List.of(2, "www.example.org")),
        certificate.getSubjectAlternativeNames().stream().toList());
    assertEquals(List.of("1.3.6.1.5.5.7.3.1"), certificate.getExtendedKeyUsage());
    assertEquals(-1, certificate.getBasicConstraints(), "CA:false");
    assertTrue(certificate.getCriticalExtensionOIDs().contains(Extension.basicConstraints.getId()));
    assertTrue(certificate.getCriticalExtensionOIDs().contains(Extension.keyUsage.getId()));
    boolean[] usage = certificate.getKeyUsage();
    assertTrue(usage[0], "digitalSignature");
    assertFalse(usage[2], "no keyEncipherment for an EC key");
    assertEquals("SHA384withECDSA", certificate.getSigAlgName());
    assertEquals(T0.minus(Duration.ofMinutes(5)), certificate.getNotBefore().toInstant());
    assertEquals(T0.plus(Duration.ofDays(7)), certificate.getNotAfter().toInstant());
    assertEquals(T0.plus(Duration.ofDays(7)), leaf.notAfter());
    assertEquals(active.id(), leaf.anchorId());
    assertEquals(certificate.getSerialNumber().toString(16), leaf.serial());
    assertEquals(32, leaf.serial().length(), "128 bits");
    // The AuthorityKeyIdentifier is the anchor's own key id.
    assertEquals(
        java.util.HexFormat.of()
            .formatHex(
                SubjectKeyIdentifier.getInstance(
                        extension(active.certificate(), Extension.subjectKeyIdentifier))
                    .getKeyIdentifier()),
        java.util.HexFormat.of()
            .formatHex(
                AuthorityKeyIdentifier.getInstance(
                        extension(certificate, Extension.authorityKeyIdentifier))
                    .getKeyIdentifierObject()
                    .getOctets()));

    List<X509Certificate> chain =
        CertificateFactory.getInstance("X.509")
            .generateCertificates(
                new ByteArrayInputStream(leaf.chainPem().getBytes(StandardCharsets.US_ASCII)))
            .stream()
            .map(X509Certificate.class::cast)
            .toList();
    assertEquals(List.of(certificate, active.certificate()), chain);
  }

  @Test
  void anRsaLeafAlsoAllowsKeyEncipherment() throws Exception {
    anchors.start();
    Leaves.Leaf leaf =
        leaves.issue("dev-qits-egress", Csrs.pem(Csrs.request(Csrs.rsa(2048), Csrs.dns("a.example.org"))));
    assertTrue(leaf.certificate().getKeyUsage()[0]);
    assertTrue(leaf.certificate().getKeyUsage()[2]);
  }

  @Test
  void aLeafNeverOutlivesTheAnchor() throws Exception {
    Anchors shortLived =
        new Anchors(
            ca,
            new AnchorPolicy(
                "dev", Duration.ofDays(3), Duration.ofDays(30), Duration.ofDays(1), Duration.ofDays(7)),
            clock);
    shortLived.start();
    Anchor active =
        shortLived.all().stream().filter(a -> a.status() == AnchorStatus.ACTIVE).findFirst().orElseThrow();

    Leaves.Leaf leaf = leaves(shortLived).issue("dev-qits-egress", Csrs.forNames("a.example.org"));

    assertEquals(active.notAfter(), leaf.notAfter());
    assertEquals(active.notAfter(), leaf.certificate().getNotAfter().toInstant());
  }

  @Test
  void aNonRequesterIsRefusedBeforeTheCsrIsRead() {
    anchors.start();
    LeafRefused refused = assertThrows(LeafRefused.class, () -> leaves.issue("dev-qits-ci", "not even a csr"));
    assertEquals(LeafRefused.Kind.NOT_REQUESTER, refused.kind());
    assertThrows(LeafRefused.class, () -> leaves.issue(null, "x"));
  }

  @Test
  void noActiveAnchorIsNoActiveAnchor() throws Exception {
    anchors.load();
    String csr = Csrs.forNames("a.example.org");
    assertEquals(
        "no anchor is ACTIVE",
        assertThrows(NoActiveAnchor.class, () -> leaves.issue("dev-qits-egress", csr)).getMessage());
  }

  @Test
  void anExpiredActiveAnchorSignsNothing() throws Exception {
    anchors.start();
    clock.advance(Duration.ofDays(1827));
    String csr = Csrs.forNames("a.example.org");
    assertEquals(
        "the ACTIVE anchor has expired",
        assertThrows(NoActiveAnchor.class, () -> leaves.issue("dev-qits-egress", csr)).getMessage());
  }

  @Test
  void theSameEntropyMakesTheSameLeaf() throws Exception {
    anchors.start();
    Leaves pinned =
        new Leaves(
            anchors,
            new LeafPolicy(List.of("dev-qits-egress"), "wohlben.eu", Duration.ofDays(7)),
            clock,
            () -> {
              try {
                SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
                random.setSeed(42L);
                return random;
              } catch (Exception e) {
                throw new IllegalStateException(e);
              }
            });
    String csr = Csrs.forNames("a.example.org");
    assertEquals(
        pinned.issue("dev-qits-egress", csr).certificatePem(),
        pinned.issue("dev-qits-egress", csr).certificatePem());
  }
}
