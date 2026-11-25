package eu.wohlben.qits.certificates.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.certificates.control.Anchor;
import eu.wohlben.qits.certificates.control.Anchors;
import eu.wohlben.qits.certificates.support.AuditLines;
import eu.wohlben.qits.certificates.support.Ca;
import eu.wohlben.qits.certificates.support.ContractCallers;
import eu.wohlben.qits.certificates.support.Csrs;
import eu.wohlben.qits.certificates.support.TestClock;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The leaf door over the ACTIVE fixture anchor, the suite's clock and the audit logger. */
@QuarkusTest
class LeavesResourceTest {

  static final String LEAVES = "/certificates/api/leaves";

  static final String REQUESTER = "dev-qits-egress";

  @Inject Ca ca;

  @Inject TestClock clock;

  @Inject Anchors anchors;

  AuditLines audit;

  @BeforeEach
  void listen() {
    audit = AuditLines.listen();
  }

  @AfterEach
  void stop() {
    audit.close();
    clock.reset();
  }

  static Response post(String authorization, String csr) {
    var request = given().contentType("application/json").body(Csrs.body(csr));
    if (authorization != null) {
      request = request.header("Authorization", authorization);
    }
    return request.post(LEAVES);
  }

  static Response asRequester(String csr) {
    return post(ContractCallers.caller(REQUESTER, Roles.SYSTEM), csr);
  }

  private Anchor active() {
    return anchors.bundle().anchors().get(0);
  }

  @Test
  void aRequesterGetsALeafSignedByTheActiveAnchor() throws Exception {
    ca.stage(Ca.ACTIVE);
    Instant now = Ca.STAGED_AT;

    Response answer = asRequester(Csrs.fixture(Csrs.TWO_NAMES));

    answer.then().statusCode(201).contentType("application/json");
    String pem = answer.path("certificate");
    String chain = answer.path("chain");
    List<X509Certificate> leaf = AnchorsResourceTest.certificates(pem);
    assertEquals(1, leaf.size());
    X509Certificate certificate = leaf.get(0);
    certificate.verify(active().certificate().getPublicKey());
    assertEquals(
        List.of(List.of(2, "api.example.org"), List.of(2, "www.example.org")),
        List.copyOf(certificate.getSubjectAlternativeNames()));
    assertEquals("CN=api.example.org", certificate.getSubjectX500Principal().getName());
    assertEquals(List.of("1.3.6.1.5.5.7.3.1"), certificate.getExtendedKeyUsage(), "serverAuth");
    assertEquals(-1, certificate.getBasicConstraints(), "CA:false");
    assertTrue(certificate.getCriticalExtensionOIDs().contains("2.5.29.19"), "basicConstraints critical");
    assertTrue(certificate.getKeyUsage()[0], "digitalSignature");
    assertEquals(now.minus(Duration.ofMinutes(5)), certificate.getNotBefore().toInstant());
    assertEquals(now.plus(Duration.ofDays(7)), certificate.getNotAfter().toInstant());
    assertEquals(pem + AnchorsResourceTest.pem(Ca.ACTIVE), chain);
    assertEquals(List.of(certificate, active().certificate()), AnchorsResourceTest.certificates(chain));
    answer
        .then()
        .body("serial", equalTo(certificate.getSerialNumber().toString(16)))
        .body("notAfter", equalTo("2026-12-02T12:00:00Z"))
        .body("anchorId", equalTo(Ca.ACTIVE));

    assertEquals(
        "certificates decision=ISSUED requester=dev-qits-egress names=api.example.org,www.example.org"
            + " serial="
            + certificate.getSerialNumber().toString(16)
            + " anchor="
            + Ca.ACTIVE
            + " notAfter=2026-12-02T12:00:00Z reason=-",
        audit.only());
  }

  @Test
  void anRsaKeyOf2048BitsIsSignedWithKeyEncipherment() throws Exception {
    ca.stage(Ca.ACTIVE);
    Response answer = asRequester(Csrs.forNames(Csrs.keys("RSA", 2048), "rsa.example.org"));
    answer.then().statusCode(201);
    X509Certificate certificate = AnchorsResourceTest.certificates(answer.path("certificate")).get(0);
    assertTrue(certificate.getKeyUsage()[0]);
    assertTrue(certificate.getKeyUsage()[2], "keyEncipherment");
  }

  @Test
  void theLeafNeverOutlivesTheAnchor() throws Exception {
    ca.stage(Ca.ACTIVE);
    Instant anchorNotAfter = active().notAfter();
    clock.set(anchorNotAfter.minus(Duration.ofDays(2)));

    Response answer = asRequester(Csrs.fixture(Csrs.TWO_NAMES));

    answer.then().statusCode(201).body("notAfter", equalTo(anchorNotAfter.toString()));
    X509Certificate certificate = AnchorsResourceTest.certificates(answer.path("certificate")).get(0);
    assertEquals(anchorNotAfter, certificate.getNotAfter().toInstant());
  }

  @Test
  void aSystemCallerThatIsNotARequesterIs403AndAudited() {
    ca.stage(Ca.ACTIVE);
    post(ContractCallers.caller("dev-qits-ci", Roles.SYSTEM), Csrs.fixture(Csrs.TWO_NAMES))
        .then()
        .statusCode(403)
        .body("error", equalTo("not a leaf requester"));
    assertEquals(
        "certificates decision=REFUSED requester=dev-qits-ci names=- serial=- anchor=- notAfter=-"
            + " reason=not a leaf requester",
        audit.only());
  }

  @Test
  void aRequesterWithoutQitsSystemIs403AndAudited() {
    ca.stage(Ca.ACTIVE);
    post(ContractCallers.caller(REQUESTER, "qits:agent"), Csrs.fixture(Csrs.TWO_NAMES))
        .then()
        .statusCode(403)
        .body("error", equalTo("not a leaf requester"));
    assertEquals(
        "certificates decision=REFUSED requester=dev-qits-egress names=- serial=- anchor=- notAfter=-"
            + " reason=not qits:system",
        audit.only());

    audit.clear();
    post(ContractCallers.caller("operator", Roles.ADMIN), Csrs.fixture(Csrs.TWO_NAMES))
        .then()
        .statusCode(403);
    assertTrue(audit.only().contains("requester=operator"));
  }

  @Test
  void anAnonymousCallerIs401() {
    ca.stage(Ca.ACTIVE);
    post(null, Csrs.fixture(Csrs.TWO_NAMES)).then().statusCode(401);
  }

  @Test
  void aRefusedNameIs400NamingItAndAudited() throws Exception {
    ca.stage(Ca.ACTIVE);
    asRequester(Csrs.fixture(Csrs.INTERNAL_NAME))
        .then()
        .statusCode(400)
        .body("error", equalTo("name refused"))
        .body("name", equalTo("db.internal"));
    assertEquals(
        "certificates decision=REFUSED requester=dev-qits-egress names=db.internal serial=- anchor=-"
            + " notAfter=- reason=name refused: db.internal is under .internal",
        audit.only());
  }

  @Test
  void everyNameRuleRefusesAtTheDoor() throws Exception {
    ca.stage(Ca.ACTIVE);
    for (String name :
        List.of(
            "*.example.org",
            "10.1.2.3",
            "localhost",
            "intranet",
            "db.internal",
            "printer.local",
            "qits.wohlben.eu",
            "idp.qits.wohlben.eu",
            "bad_name.example.org")) {
      asRequester(Csrs.forNames("fine.example.org", name))
          .then()
          .statusCode(400)
          .body("error", equalTo("name refused"))
          .body("name", equalTo(name));
    }
    assertEquals(9, audit.lines().size());
    audit.lines().forEach(l -> assertTrue(l.message().contains("decision=REFUSED"), l.message()));
  }

  @Test
  void aCsrTheRulesRefuseIs400WithItsReason() throws Exception {
    ca.stage(Ca.ACTIVE);
    asRequester(Csrs.forNames(Csrs.keys("EC", "secp384r1"), "a.example.org"))
        .then()
        .statusCode(400)
        .body("error", equalTo("the key is EC on a curve other than P-256"))
        .body("name", org.hamcrest.Matchers.nullValue());
    asRequester(Csrs.forNames(Csrs.keys("RSA", 1024), "a.example.org"))
        .then()
        .statusCode(400)
        .body("error", equalTo("the RSA key has 1024 bits, fewer than 2048"));
    asRequester("not a csr").then().statusCode(400).body("error", equalTo("the csr is not a PKCS#10 PEM"));
    given()
        .contentType("application/json")
        .header("Authorization", ContractCallers.caller(REQUESTER, Roles.SYSTEM))
        .body("{}")
        .post(LEAVES)
        .then()
        .statusCode(400)
        .body("error", equalTo("the request carries no csr"));
    assertEquals(4, audit.lines().size());
  }

  @Test
  void noActiveAnchorIs503() {
    ca.empty();
    asRequester(Csrs.fixture(Csrs.TWO_NAMES))
        .then()
        .statusCode(503)
        .body("error", equalTo("no anchor is ACTIVE"));
    String line = audit.only();
    assertTrue(line.startsWith("certificates decision=REFUSED requester=dev-qits-egress"), line);
    assertTrue(line.endsWith("reason=no anchor is ACTIVE"), line);
    assertFalse(line.contains("PRIVATE KEY"));
    ca.boot();
  }
}
