package eu.wohlben.qits.certificates.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.stream.IntStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** Every rule of {@link LeafPolicy}, one by one. */
class LeafPolicyTest {

  static final LeafPolicy POLICY =
      new LeafPolicy(List.of("dev-qits-egress", " ", "dev-other"), "wohlben.eu", Duration.ofDays(7));

  private static LeafRefused refused(String pem) {
    return assertThrows(LeafRefused.class, () -> POLICY.check(pem));
  }

  @Test
  void onlyTheListedRequestersAreAdmitted() {
    assertTrue(POLICY.admits("dev-qits-egress"));
    assertTrue(POLICY.admits("dev-other"));
    assertFalse(POLICY.admits("dev-qits-ci"));
    assertFalse(POLICY.admits(""));
    assertFalse(POLICY.admits(null));
    assertEquals(2, POLICY.requesters().size(), "the blank entry is dropped");
  }

  @Test
  void aGoodCsrYieldsItsNamesLowerCasedAndFolded() throws Exception {
    LeafPolicy.Request request =
        POLICY.check(Csrs.forNames("API.example.org", "www.example.org", "api.EXAMPLE.org"));
    assertEquals(List.of("api.example.org", "www.example.org"), request.names());
    assertFalse(request.rsa());
  }

  @ParameterizedTest
  @CsvSource({
    "*.example.org, a wildcard",
    "a.*.example.org, a wildcard",
    "localhost, localhost",
    "api.localhost, localhost",
    "intranet, a single-label name",
    "db.internal, under .internal",
    "printer.local, under .local",
    "qits.wohlben.eu, a platform host under qits.wohlben.eu",
    "idp.qits.wohlben.eu, a platform host under qits.wohlben.eu",
    "a.b.qits.wohlben.eu, a platform host under qits.wohlben.eu",
    "10.0.0.1, an IP address",
    "-bad.example.org, not a valid hostname",
    "bad-.example.org, not a valid hostname",
    "under_score.example.org, not a valid hostname",
    "double..dot.org, not a valid hostname",
    "trailing.dot.org., not a valid hostname",
    "example.123, not a valid hostname"
  })
  void eachNameRuleRefusesWithTheName(String name, String why) throws Exception {
    LeafRefused refused = refused(Csrs.forNames("fine.example.org", name));
    assertEquals(LeafRefused.Kind.NAME, refused.kind());
    assertEquals(name, refused.name());
    assertEquals("name refused: " + name + " is " + why, refused.reason());
    assertEquals(List.of("fine.example.org", name), refused.names());
  }

  @Test
  void aNameTooLongIsNotAValidHostname() throws Exception {
    String label = "a".repeat(64);
    assertEquals(LeafRefused.Kind.NAME, refused(Csrs.forNames(label + ".example.org")).kind());
    String long253 = String.join(".", List.of("a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61)));
    assertEquals(253, long253.length());
    assertNull(POLICY.refusal(long253), "253 characters is the most a name may be");
    assertEquals("not a valid hostname", POLICY.refusal(long253 + "e"));
  }

  @Test
  void namesThatOnlyResembleThePlatformDomainPass() {
    assertNull(POLICY.refusal("qits.wohlben.eu.example.org"));
    assertNull(POLICY.refusal("notqits.wohlben.eu"));
    assertNull(POLICY.refusal("wohlben.eu"));
    assertNull(POLICY.refusal("internal.example.org"));
  }

  @Test
  void aBlankDomainRefusesNoPlatformHost() {
    LeafPolicy blank = new LeafPolicy(List.of("x"), " ", Duration.ofDays(7));
    assertTrue(blank.domain().isEmpty());
    assertNull(blank.refusal("idp.qits.wohlben.eu"));
    assertEquals("under .local", blank.refusal("printer.local"));
  }

  @Test
  void anIpAddressSanIsRefusedAsAName() throws Exception {
    GeneralName ip =
        new GeneralName(
            GeneralName.iPAddress, new DEROctetString(InetAddress.getByName("192.0.2.7").getAddress()));
    LeafRefused refused =
        refused(
            Csrs.pem(
                Csrs.request(
                    Csrs.ec("secp256r1"), new GeneralName(GeneralName.dNSName, "a.example.org"), ip)));
    assertEquals(LeafRefused.Kind.NAME, refused.kind());
    assertEquals("192.0.2.7", refused.name());
  }

  @Test
  void aNameOfAnotherKindIsACsrRefusal() throws Exception {
    LeafRefused refused =
        refused(
            Csrs.pem(
                Csrs.request(
                    Csrs.ec("secp256r1"), new GeneralName(GeneralName.rfc822Name, "a@example.org"))));
    assertEquals(LeafRefused.Kind.CSR, refused.kind());
    assertEquals("the csr requests a name that is not a dNSName", refused.reason());
  }

  @Test
  void noNamesAndTooManyNamesAreRefused() throws Exception {
    assertEquals(
        "the csr requests no names",
        refused(Csrs.pem(Csrs.request(Csrs.ec("secp256r1"), (GeneralName[]) null))).reason());
    String[] ten = IntStream.range(0, 10).mapToObj(i -> "n" + i + ".example.org").toArray(String[]::new);
    assertEquals(10, POLICY.check(Csrs.forNames(ten)).names().size());
    String[] eleven = IntStream.range(0, 11).mapToObj(i -> "n" + i + ".example.org").toArray(String[]::new);
    LeafRefused refused = refused(Csrs.forNames(eleven));
    assertEquals(LeafRefused.Kind.CSR, refused.kind());
    assertEquals("the csr requests 11 names, more than 10", refused.reason());
  }

  @Test
  void theKeyMustBeP256OrRsaOfAtLeast2048Bits() throws Exception {
    LeafRefused p384 =
        refused(Csrs.pem(Csrs.request(Csrs.ec("secp384r1"), Csrs.dns("a.example.org"))));
    assertEquals(LeafRefused.Kind.CSR, p384.kind());
    assertEquals("the key is EC on a curve other than P-256", p384.reason());

    LeafRefused rsa1024 = refused(Csrs.pem(Csrs.request(Csrs.rsa(1024), Csrs.dns("a.example.org"))));
    assertEquals("the RSA key has 1024 bits, fewer than 2048", rsa1024.reason());

    LeafPolicy.Request rsa2048 =
        POLICY.check(Csrs.pem(Csrs.request(Csrs.rsa(2048), Csrs.dns("a.example.org"))));
    assertTrue(rsa2048.rsa());
  }

  @Test
  void aSignatureThatDoesNotVerifyIsRefused() throws Exception {
    LeafRefused refused =
        refused(
            Csrs.pem(
                Csrs.tampered(Csrs.request(Csrs.ec("secp256r1"), Csrs.dns("a.example.org")))));
    assertEquals(LeafRefused.Kind.CSR, refused.kind());
    assertEquals("the csr's signature does not verify", refused.reason());
  }

  @Test
  void anythingButAPkcs10PemIsRefused() {
    assertEquals("the request carries no csr", refused(null).reason());
    assertEquals("the request carries no csr", refused("  ").reason());
    assertEquals("the csr is not a PKCS#10 PEM", refused("not a pem").reason());
    assertEquals(
        "the csr is not a PKCS#10 PEM",
        refused("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n").reason());
    assertEquals(
        "the csr is longer than 16384 characters", refused("x".repeat(LeafPolicy.MAX_CSR + 1)).reason());
  }

  @Test
  void theValidityIsCappedAtTheAnchorsNotAfter() {
    Instant now = Instant.parse("2026-11-25T12:00:00Z");
    assertEquals(now.plus(Duration.ofDays(7)), POLICY.notAfter(now, now.plus(Duration.ofDays(30))));
    Instant soon = now.plus(Duration.ofDays(2));
    assertEquals(soon, POLICY.notAfter(now, soon));
  }

  @Test
  void printableReplacesControlCharactersAndCuts() {
    assertEquals("a?b?c", LeafPolicy.printable("a\nb c"));
    assertEquals(255, LeafPolicy.printable("x".repeat(300)).length());
  }
}
