package eu.wohlben.qits.certificates.control;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The anchors on a temp volume, with a clock the test moves. */
class AnchorsTest {

  static final Instant T0 = Instant.parse("2026-11-25T10:00:00Z");

  @TempDir Path ca;

  MutableClock clock;

  Anchors anchors;

  @BeforeEach
  void boot() {
    clock = new MutableClock(T0);
    anchors = new Anchors(ca, AnchorPolicy.defaults("dev"), clock);
  }

  private List<AnchorStatus> statuses() {
    return anchors.all().stream().map(Anchor::status).toList();
  }

  private Anchor only(AnchorStatus status) {
    List<Anchor> found = anchors.all().stream().filter(a -> a.status() == status).toList();
    assertEquals(1, found.size(), status + " anchors: " + found);
    return found.get(0);
  }

  @Test
  void firstBootMakesOneActiveAnchorOnTheVolume() throws Exception {
    anchors.start();

    Anchor active = only(AnchorStatus.ACTIVE);
    assertEquals(1, anchors.all().size());
    Path dir = ca.resolve("anchors").resolve(active.id());
    assertEquals(dir, active.directory());
    assertEquals("rw-r--r--", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir.resolve("cert.pem"))));
    assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir.resolve("key.pem"))));
    assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir)));
    assertTrue(Files.readString(dir.resolve("key.pem")).startsWith("-----BEGIN PRIVATE KEY-----\n"));
    try (Stream<Path> left = Files.list(ca.resolve("anchors"))) {
      assertEquals(List.of(dir), left.toList(), "no staging directory is left behind");
    }
    try (Stream<Path> left = Files.list(dir)) {
      assertEquals(3, left.count(), "no temp file is left behind");
    }

    AnchorState state = AnchorState.parse(Files.readString(dir.resolve("state.json")));
    assertEquals(active.id(), state.id());
    assertEquals(AnchorStatus.ACTIVE, state.status());
    assertEquals(T0, state.createdAt());
    assertEquals(T0, state.activatesAt());
    assertNull(state.retiresAt());
    assertEquals(T0.plus(Duration.ofDays(1826)), state.notAfter());
    assertEquals(AnchorCrypto.sha256(active.certificate()), state.sha256());

    assertTrue(anchors.readiness().up());
    assertEquals(active, anchors.readiness().active());
  }

  @Test
  void theAnchorIsAP384CaWithTheSpecifiedSubjectAndExtensions() throws Exception {
    anchors.start();
    X509Certificate cert = only(AnchorStatus.ACTIVE).certificate();

    assertEquals("CN=qits platform CA dev 2026-11, O=qits", only(AnchorStatus.ACTIVE).subject());
    assertEquals("CN=qits platform CA dev 2026-11, O=qits", cert.getSubjectX500Principal().toString());
    assertEquals(cert.getSubjectX500Principal(), cert.getIssuerX500Principal());
    assertEquals("SHA384withECDSA", cert.getSigAlgName());
    assertEquals("EC", cert.getPublicKey().getAlgorithm());
    assertTrue(cert.getPublicKey().toString().contains("secp384r1"), cert.getPublicKey().toString());
    assertEquals(0, cert.getBasicConstraints(), "CA:true, pathLen 0");
    assertTrue(cert.getCriticalExtensionOIDs().contains(Extension.basicConstraints.getId()));
    assertTrue(cert.getCriticalExtensionOIDs().contains(Extension.keyUsage.getId()));
    boolean[] usage = cert.getKeyUsage();
    assertTrue(usage[5], "keyCertSign");
    assertTrue(usage[6], "cRLSign");
    assertFalse(usage[0], "no digitalSignature");
    assertTrue(cert.getNonCriticalExtensionOIDs().contains(Extension.subjectKeyIdentifier.getId()));
    assertTrue(ASN1OctetString.getInstance(cert.getExtensionValue(Extension.subjectKeyIdentifier.getId())).getOctets().length > 0);
    assertEquals(128, cert.getSerialNumber().bitLength());
    assertEquals(T0.minus(Duration.ofMinutes(5)), cert.getNotBefore().toInstant());
    assertEquals(T0.plus(Duration.ofDays(1826)), cert.getNotAfter().toInstant());
    cert.verify(cert.getPublicKey());
  }

  @Test
  void aRestartReloadsTheSameAnchor() {
    anchors.start();
    Anchor first = only(AnchorStatus.ACTIVE);

    Anchors restarted = new Anchors(ca, AnchorPolicy.defaults("dev"), clock);
    restarted.start();

    assertEquals(1, restarted.all().size());
    Anchor again = restarted.all().get(0);
    assertEquals(first.id(), again.id());
    assertEquals(first.state(), again.state());
    assertEquals(first.certificatePem(), again.certificatePem());
    assertEquals(anchors.bundle().version(), restarted.bundle().version());
  }

  @Test
  void theRotationPathRunsOnTheClock() throws Exception {
    anchors.start();
    Anchor first = only(AnchorStatus.ACTIVE);
    String firstOnly = anchors.bundle().pem();

    // A year and a day before notAfter is still outside renew-before: nothing happens.
    clock.set(first.state().notAfter().minus(Duration.ofDays(366)));
    anchors.tick();
    assertEquals(List.of(AnchorStatus.ACTIVE), statuses());

    // Inside renew-before: a PENDING anchor, ACTIVE after the overlap.
    clock.set(first.state().notAfter().minus(Duration.ofDays(364)));
    Instant renewAt = clock.instant();
    anchors.tick();
    Anchor pending = only(AnchorStatus.PENDING);
    assertEquals(renewAt.plus(Duration.ofDays(30)), pending.state().activatesAt());
    assertEquals(List.of(first.id(), pending.id()), ids(anchors.bundle().anchors()));
    assertEquals(firstOnly + pending.certificatePem(), anchors.bundle().pem());
    anchors.tick();
    assertEquals(1, anchors.all().stream().filter(a -> a.status() == AnchorStatus.PENDING).count(), "never two PENDING");

    // Before activatesAt: still PENDING.
    clock.set(pending.state().activatesAt().minusSeconds(1));
    anchors.tick();
    assertEquals(pending.id(), only(AnchorStatus.PENDING).id());

    // At activatesAt: it is ACTIVE, the old one RETIRING for leaf validity plus a day.
    clock.set(pending.state().activatesAt());
    Instant activation = clock.instant();
    anchors.tick();
    assertEquals(pending.id(), only(AnchorStatus.ACTIVE).id());
    Anchor retiring = only(AnchorStatus.RETIRING);
    assertEquals(first.id(), retiring.id());
    assertEquals(activation.plus(Duration.ofDays(8)), retiring.state().retiresAt());
    assertEquals(List.of(pending.id(), first.id()), ids(anchors.bundle().anchors()), "ACTIVE first");
    assertEquals(pending.certificatePem() + first.certificatePem(), anchors.bundle().pem());
    assertTrue(anchors.readiness().up());
    assertEquals(pending.id(), anchors.readiness().active().id());

    // At retiresAt: RETIRED, out of the bundle, its key deleted and its certificate kept.
    clock.set(retiring.state().retiresAt());
    anchors.tick();
    Anchor retired = only(AnchorStatus.RETIRED);
    assertEquals(first.id(), retired.id());
    assertFalse(Files.exists(retired.directory().resolve("key.pem")));
    assertTrue(Files.exists(retired.directory().resolve("cert.pem")));
    assertEquals(List.of(pending.id()), ids(anchors.bundle().anchors()));
    assertEquals(pending.certificatePem(), anchors.bundle().pem());

    // The whole history survives a restart.
    Anchors restarted = new Anchors(ca, AnchorPolicy.defaults("dev"), clock);
    restarted.start();
    assertEquals(anchors.all().stream().map(Anchor::state).toList(), restarted.all().stream().map(Anchor::state).toList());
  }

  @Test
  void aRotationByRequestIsPendingAndOnlyOnce() {
    anchors.start();
    Anchor made = anchors.rotate();
    assertEquals(AnchorStatus.PENDING, made.status());
    assertEquals(T0.plus(Duration.ofDays(30)), made.state().activatesAt());
    PendingAnchorExists refused = assertThrows(PendingAnchorExists.class, anchors::rotate);
    assertEquals(made.id(), refused.anchorId());
  }

  @Test
  void aPendingAnchorTakesOverWhenNoneIsActive() throws Exception {
    anchors.start();
    Anchor first = only(AnchorStatus.ACTIVE);
    Anchor pending = anchors.rotate();
    // A crash after the old ACTIVE was demoted and before the PENDING was promoted.
    Files.writeString(
        first.directory().resolve("state.json"),
        first.state().retiring(T0.plus(Duration.ofDays(8))).toJson());
    Anchors restarted = new Anchors(ca, AnchorPolicy.defaults("dev"), clock);
    restarted.start();
    assertEquals(pending.id(), restarted.readiness().active().id());
    assertTrue(restarted.readiness().up());
  }

  @Test
  void aCorruptDirectoryIsIgnoredAndKept() throws Exception {
    anchors.start();
    Anchor good = only(AnchorStatus.ACTIVE);
    Path anchorsDir = ca.resolve("anchors");

    Path malformed = Files.createDirectory(anchorsDir.resolve("malformed"));
    Files.writeString(malformed.resolve("state.json"), "{not json");
    Path mismatched = anchorsDir.resolve("mismatched");
    Files.createDirectory(mismatched);
    Anchors other = new Anchors(Files.createTempDirectory(ca, "other"), AnchorPolicy.defaults("dev"), clock);
    other.start();
    Anchor foreign = other.all().get(0);
    // The good anchor's certificate and state, beside a key that is not its own.
    Files.copy(good.directory().resolve("cert.pem"), mismatched.resolve("cert.pem"));
    Files.copy(foreign.directory().resolve("key.pem"), mismatched.resolve("key.pem"));
    Files.writeString(
        mismatched.resolve("state.json"),
        new AnchorState("mismatched", AnchorStatus.PENDING, T0, T0, null, good.notAfter(), good.state().sha256()).toJson());
    Path stray = Files.writeString(anchorsDir.resolve("stray.txt"), "not an anchor");

    Anchors restarted = new Anchors(ca, AnchorPolicy.defaults("dev"), clock);
    restarted.start();

    assertEquals(List.of(good.id()), ids(restarted.all()));
    assertTrue(restarted.readiness().up());
    assertTrue(Files.exists(malformed.resolve("state.json")));
    assertTrue(Files.exists(mismatched.resolve("key.pem")));
    assertTrue(Files.exists(stray));
  }

  @Test
  void readinessIsDownWithoutAnActiveAnchorOrItsKey() throws Exception {
    assertFalse(anchors.readiness().up(), "nothing loaded yet");
    anchors.load();
    assertFalse(anchors.readiness().up(), "an empty volume holds no anchor");

    anchors.start();
    Anchor active = only(AnchorStatus.ACTIVE);
    Files.delete(active.directory().resolve("key.pem"));
    assertFalse(anchors.readiness().up(), "the key is gone");
    assertFalse(anchors.readiness().reason().contains("PRIVATE KEY"));
  }

  @Test
  void theBundleVersionIsTheSha256OfItsPem() {
    anchors.start();
    Anchors.Bundle bundle = anchors.bundle();
    assertEquals(AnchorCrypto.sha256(bundle.pem().getBytes(StandardCharsets.US_ASCII)), bundle.version());
    assertEquals(64, bundle.version().length());
  }

  @Test
  void theBundleParsesAsCertificatesOnly() throws Exception {
    anchors.start();
    anchors.rotate();
    String pem = anchors.bundle().pem();
    assertFalse(pem.contains("PRIVATE KEY"));
    var parsed =
        CertificateFactory.getInstance("X.509")
            .generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    assertEquals(2, parsed.size());
    X509Certificate first = (X509Certificate) parsed.iterator().next();
    assertArrayEquals(only(AnchorStatus.ACTIVE).certificate().getEncoded(), first.getEncoded(), "ACTIVE first");
  }

  @Test
  void bouncyCastleIsNotARegisteredProvider() {
    // The design's rule: the JDK's SunEC signs; Bouncy Castle builds and parses structures only.
    anchors.start();
    assertEquals(
        List.of(),
        Arrays.stream(Security.getProviders()).map(p -> p.getName()).filter("BC"::equals).toList());
  }

  private static List<String> ids(List<Anchor> list) {
    return list.stream().map(Anchor::id).toList();
  }
}
