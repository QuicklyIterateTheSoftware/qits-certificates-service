package eu.wohlben.qits.certificates.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.auth.WorkloadPrincipal;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The workload certificate door (qits-2756) over the ACTIVE fixture anchor, the suite's clock and
 * the audit logger. Callers are tokens with claims ({@link ContractCallers#token}), as quarkus-oidc
 * leaves them; the environment is the suite's {@code dev}.
 */
@QuarkusTest
class WorkloadCertificatesResourceTest {

  static final String DOOR = "/certificates/api/workload-certificates";

  static final String AGENT = "6fe232fc-0000-4000-8000-000000000001";

  static final String PROJECT = "8273c743-e0bb-4d93-90d4-391aa10d9151";

  @Inject Ca ca;

  @Inject TestClock clock;

  @Inject Anchors anchors;

  AuditLines audit;

  @BeforeEach
  void listen() {
    ca.stage(Ca.ACTIVE);
    audit = AuditLines.listen();
  }

  @AfterEach
  void stop() {
    audit.close();
    clock.reset();
  }

  static Map<String, Object> claims(String sub, Object... pairs) {
    Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("sub", sub);
    for (int i = 0; i < pairs.length; i += 2) {
      claims.put((String) pairs[i], pairs[i + 1]);
    }
    return claims;
  }

  static Map<String, Object> service(String application) {
    String sub = "dev-" + application;
    return claims(sub, "groups", List.of(Roles.SYSTEM, "clients/" + sub), "project", "*");
  }

  static Response post(String authorization, String csr) {
    var request = given().contentType("application/json").body(Csrs.body(csr));
    if (authorization != null) {
      request = request.header("Authorization", authorization);
    }
    return request.post(DOOR);
  }

  static Response as(Map<String, Object> claims, String csr) {
    return post(ContractCallers.token(claims, Roles.SYSTEM), csr);
  }

  static X509Certificate certificate(Response answer) throws Exception {
    return AnchorsResourceTest.certificates(answer.path("certificate")).get(0);
  }

  @Test
  void aServiceBearerGetsACertificateNamingItsApplication() throws Exception {
    Response answer = as(service("qits-edge"), Csrs.fixture(Csrs.TWO_NAMES));

    answer.then().statusCode(201).contentType("application/json").body(not(containsString("PRIVATE KEY")));
    X509Certificate certificate = certificate(answer);
    certificate.verify(anchors.bundle().anchors().get(0).certificate().getPublicKey());
    assertEquals(
        List.of(List.of(6, "urn:qits:principal:application:qits-edge"), List.of(2, "dev-qits-edge")),
        List.copyOf(certificate.getSubjectAlternativeNames()),
        "the CSR's api.example.org and www.example.org never reach it");
    assertEquals("CN=application:qits-edge", certificate.getSubjectX500Principal().getName());
    assertEquals(
        List.of("1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1"), certificate.getExtendedKeyUsage());
    assertEquals(
        new WorkloadPrincipal("application", "qits-edge"),
        WorkloadPrincipal.fromCertificate(certificate),
        "the acceptor reads back what the issuer wrote");
    answer
        .then()
        .body("principal", equalTo("application:qits-edge"))
        .body("anchorId", equalTo(Ca.ACTIVE))
        .body("notAfter", equalTo(Ca.STAGED_AT.plus(Duration.ofDays(1)).toString()))
        .body("serial", equalTo(certificate.getSerialNumber().toString(16)));
    assertEquals(
        "certificates decision=ISSUED kind=workload requester=dev-qits-edge"
            + " principal=application:qits-edge"
            + " names=urn:qits:principal:application:qits-edge,dev-qits-edge serial="
            + certificate.getSerialNumber().toString(16)
            + " anchor="
            + Ca.ACTIVE
            + " notAfter="
            + Ca.STAGED_AT.plus(Duration.ofDays(1))
            + " reason=-",
        audit.only());
  }

  @Test
  void anAgentBearerGetsACertificateNamingTheAgentAndProject() throws Exception {
    Map<String, Object> agent =
        claims("tok-workspace-agent-x", "groups", List.of("qits:agent"), "agent", AGENT, "project", PROJECT);
    Response answer = post(ContractCallers.token(agent, "qits:agent"), Csrs.forNames("evil.example.org"));

    answer.then().statusCode(201).body("principal", equalTo("agent:" + AGENT));
    X509Certificate certificate = certificate(answer);
    assertEquals(
        List.of(
            List.of(6, "urn:qits:principal:agent:" + AGENT),
            List.of(6, "urn:qits:project:" + PROJECT)),
        List.copyOf(certificate.getSubjectAlternativeNames()));
    assertEquals(List.of("1.3.6.1.5.5.7.3.2"), certificate.getExtendedKeyUsage(), "clientAuth only");
    assertEquals(
        new WorkloadPrincipal("agent", AGENT, PROJECT), WorkloadPrincipal.fromCertificate(certificate));
  }

  @Test
  void aProjectBearerGetsItsProject() throws Exception {
    Map<String, Object> project =
        claims("tok-project-agent-qits-developer", "groups", List.of("qits:agent"), "project", PROJECT);
    post(ContractCallers.token(project, "qits:agent"), Csrs.fixture(Csrs.TWO_NAMES))
        .then()
        .statusCode(201)
        .body("principal", equalTo("project:" + PROJECT));
  }

  @Test
  void aForeignEnvironmentsServiceClientIsNotAnApplication() throws Exception {
    Map<String, Object> prod =
        claims("prod-qits-edge", "groups", List.of(Roles.SYSTEM, "clients/prod-qits-edge"), "project", "*");
    as(prod, Csrs.fixture(Csrs.TWO_NAMES))
        .then()
        .statusCode(403)
        .body("error", equalTo("a name unfit for a certificate"));
  }

  @Test
  void aPersonsTokenIs403AndAudited() {
    Map<String, Object> person =
        claims("6b0c1f4e-0000-4000-8000-00000000000a", "groups", List.of(Roles.ADMIN), "credential_type", "cli");
    post(ContractCallers.token(person, Roles.ADMIN), Csrs.fixture(Csrs.TWO_NAMES))
        .then()
        .statusCode(403)
        .body("error", equalTo("a person's token"));
    assertEquals(
        "certificates decision=REFUSED kind=workload requester=6b0c1f4e-0000-4000-8000-00000000000a"
            + " principal=subject:6b0c1f4e-0000-4000-8000-00000000000a names=- serial=- anchor=-"
            + " notAfter=- reason=a person's token",
        audit.only());
  }

  @Test
  void anExchangedTokenIs403() {
    Map<String, Object> exchanged = service("qits-edge");
    exchanged.put("act", Map.of("sub", "dev-qits-egress"));
    as(exchanged, Csrs.fixture(Csrs.TWO_NAMES))
        .then()
        .statusCode(403)
        .body("error", equalTo("an exchanged token"));
  }

  @Test
  void aTokenOfNoWorkloadIs403() {
    as(claims("someone", "groups", List.of(Roles.SYSTEM)), Csrs.fixture(Csrs.TWO_NAMES))
        .then()
        .statusCode(403)
        .body("error", equalTo("no workload principal"));
  }

  @Test
  void anIdentityWithoutATokenIs403() {
    post(ContractCallers.caller("dev-qits-edge", Roles.SYSTEM), Csrs.fixture(Csrs.TWO_NAMES))
        .then()
        .statusCode(403)
        .body("error", equalTo("no workload principal"));
  }

  @Test
  void noBearerIs401AndAudited() {
    post(null, Csrs.fixture(Csrs.TWO_NAMES))
        .then()
        .statusCode(401)
        .body("error", equalTo("a bearer token is required"));
    assertEquals(
        "certificates decision=REFUSED kind=workload requester=- principal=- names=- serial=-"
            + " anchor=- notAfter=- reason=no bearer",
        audit.only());
  }

  @Test
  void aBadCsrIs400AndAudited() throws Exception {
    as(service("qits-edge"), "not a csr")
        .then()
        .statusCode(400)
        .body("error", equalTo("the csr is not a PKCS#10 PEM"));
    assertTrue(audit.only().endsWith("reason=the csr is not a PKCS#10 PEM"));
    audit.clear();
    as(service("qits-edge"), Csrs.forNames(Csrs.keys("EC", "secp384r1"), "a.example.org"))
        .then()
        .statusCode(400)
        .body("error", equalTo("the key is EC on a curve other than P-256"));
  }

  @Test
  void theCertificateNeverOutlivesTheAnchor() throws Exception {
    java.time.Instant anchorNotAfter = anchors.bundle().anchors().get(0).notAfter();
    clock.set(anchorNotAfter.minus(Duration.ofHours(3)));
    as(service("qits-edge"), Csrs.fixture(Csrs.TWO_NAMES))
        .then()
        .statusCode(201)
        .body("notAfter", equalTo(anchorNotAfter.toString()));
  }

  @Test
  void withoutAnActiveAnchorIs503() {
    ca.empty();
    as(service("qits-edge"), Csrs.fixture(Csrs.TWO_NAMES)).then().statusCode(503);
  }
}
