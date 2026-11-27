package eu.wohlben.qits.certificates.stories.bootstrap;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;

import eu.wohlben.qits.servicemock.idp.MockIdp;
import eu.wohlben.qits.userflows.Interactions;
import eu.wohlben.qits.userflows.NetworkCapture;
import eu.wohlben.qits.userflows.NetworkTaps;
import eu.wohlben.qits.userflows.UserStory;
import eu.wohlben.qits.userflows.UserStoryDescription;
import eu.wohlben.qits.userflows.report.ReportAssertions;
import eu.wohlben.qits.userflows.report.UserflowReport;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

/**
 * The service as it is <b>packaged</b> — the fast-jar in a plain {@code ./mvnw verify}, the native
 * binary under {@code ./mvnw verify -Dnative} — with the OIDC tenant <b>on</b> against
 * {@link MockIdp}, the shipped validation block no {@code @QuarkusTest} here exercises.
 *
 * <p>THIS IS THE NATIVE IT (qits-2646, qits-2647; the leaf door's signing is {@code
 * leaves/LeafIssuanceIT}, on the same profile). The launched process boots on an empty CA
 * volume, so it makes its first ACTIVE anchor itself: an EC P-384 key from the JDK, a self-signed
 * certificate built, written as PEM and parsed back by Bouncy Castle's bcpkix. Against the binary
 * that proves the native image carries everything the anchors need — the known risk of this
 * service, which a green JVM suite cannot see — and the anchors door then serves what it made.
 *
 * <p>It is also this repository's <b>userflow catalogue</b>: the story's documentation is written
 * under {@code service/target/userstories/}, which the java-service release recipe requires and
 * publishes as {@code @userflows/qits-certificates}.
 */
@QuarkusIntegrationTest
@TestProfile(CertificatesBootstrapIT.PackagedWithMockIdp.class)
public class CertificatesBootstrapIT {

  static final String CATEGORY = "bootstrap";

  static final String SLUG = "the-certificate-authority-starts-with-its-first-trust-anchor";

  static final String SERVICE = "qits-certificates";

  /** The one {@code sub} the packaged process admits to the leaf door. */
  public static final String LEAF_REQUESTER = "dev-qits-egress";

  /**
   * The packaged process's environment: the gate on, the idp moved to the mock, telemetry dark,
   * and the CA volume a fresh temp directory (the image's /work/ca does not exist here). Every key
   * is a RUNTIME key: a packaged artifact takes its configuration as {@code -D} arguments.
   */
  public static class PackagedWithMockIdp implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
      MockIdp idp = MockIdp.ensureStarted();
      Map<String, String> overrides = new LinkedHashMap<>();
      overrides.put("qits.auth.machine.required", "true");
      overrides.put("quarkus.oidc.auth-server-url", idp.baseUrl());
      overrides.put("quarkus.otel.sdk.disabled", "true");
      // The leaf requester the leaf story calls as, spelled out rather than left to the
      // QITS_ENVIRONMENT of whichever machine runs the suite.
      overrides.put("qits.certificates.leaf.requesters", LEAF_REQUESTER);
      // The workload story's service client is dev-qits-edge: the environment its sub is read in.
      overrides.put("qits.certificates.environment", "dev");
      try {
        overrides.put(
            "qits.certificates.ca-dir", Files.createTempDirectory("qits-certificates-ca").toString());
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      }
      return overrides;
    }
  }

  /**
   * Every path is an edge, probes included: the shipped tap skips {@code /q/} paths, but the
   * readiness the deploy gates on is half of this story.
   */
  @BeforeAll
  static void tapTheNetwork() {
    NetworkTaps.restAssured(SERVICE, path -> false);
  }

  @UserStory(value = "The certificate authority starts with its first trust anchor", category = CATEGORY)
  @UserStoryDescription(
      """
      qits-certificates holds the platform's trust anchors and signs leaf certificates. On its
      first boot, on an empty volume, it makes its first anchor: an EC P-384 key and a self-signed
      CA certificate, kept under /work/ca/anchors/<id>/. It reports ready only once exactly one
      anchor is ACTIVE and its key reads back, so the deploy never puts a CA without one in front of
      a caller. Anyone may then fetch the bundle of trust anchors, as PEM or as JSON.
      """)
  void theCertificateAuthorityStarts(Interactions story) throws Exception {
    story.note("qits-certificates starts on an empty CA volume, beside a reachable qits-idp");
    NetworkCapture.actor("the deployer's health gate");
    given()
        .get("/certificates/q/health/ready")
        .then()
        .statusCode(200)
        .body("status", equalTo("UP"))
        .body("checks.find { it.name == 'certificates-anchors' }.status", equalTo("UP"))
        .body(
            "checks.find { it.name == 'certificates-anchors' }.data.subject",
            startsWith("CN=qits platform CA dev "))
        .body(not(containsString("PRIVATE KEY")));
    story.note("readiness is UP: the first anchor was made and is ACTIVE").as("anchor-ready");

    NetworkCapture.actor("a platform container");
    String pem =
        given()
            .get("/certificates/api/anchors")
            .then()
            .statusCode(200)
            .contentType(startsWith("text/plain"))
            .body(not(containsString("PRIVATE KEY")))
            .extract()
            .asString();
    var certificates =
        CertificateFactory.getInstance("X.509")
            .generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    assertEquals(1, certificates.size());
    X509Certificate anchor = (X509Certificate) certificates.iterator().next();
    assertEquals(0, anchor.getBasicConstraints(), "the anchor is CA:TRUE, pathLen 0");
    anchor.verify(anchor.getPublicKey());
    story.note("the bundle holds the one ACTIVE anchor, a CA certificate").as("bundle");

    given()
        .header("Accept", "application/json")
        .get("/certificates/api/anchors")
        .then()
        .statusCode(200)
        .body("anchors[0].status", equalTo("ACTIVE"))
        .body("anchors[0].subject", equalTo(anchor.getSubjectX500Principal().toString()));
    story.note("as JSON, the same anchor with its version").as("bundle-json");

    given().get("/certificates/q/health/live").then().statusCode(200);
    story.note("liveness is UP").as("live");
  }

  @AfterAll
  static void theStoryReportIsComplete() {
    ReportAssertions.assertComplete(CATEGORY, SLUG, UserflowReport.PASSED);
    ReportAssertions.assertEdge(
        CATEGORY,
        SLUG,
        "http",
        "the deployer's health gate",
        SERVICE,
        "GET /certificates/q/health/ready -> 200");
    ReportAssertions.assertEdge(
        CATEGORY, SLUG, "http", "a platform container", SERVICE, "GET /certificates/api/anchors -> 200");
    ReportAssertions.assertStepId(CATEGORY, SLUG, "live");
  }
}
