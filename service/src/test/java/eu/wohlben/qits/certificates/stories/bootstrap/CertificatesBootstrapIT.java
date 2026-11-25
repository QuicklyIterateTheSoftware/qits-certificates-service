package eu.wohlben.qits.certificates.stories.bootstrap;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;

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
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

/**
 * The service as it is <b>packaged</b> — the fast-jar in a plain {@code ./mvnw verify}, the native
 * binary under {@code ./mvnw verify -Dnative} — with the OIDC tenant <b>on</b> against
 * {@link MockIdp}, the shipped validation block no {@code @QuarkusTest} here exercises.
 *
 * <p>THIS IS THE NATIVE IT (qits-2646). Its readiness check {@code certificates-crypto} signs a CSR
 * end to end with Bouncy Castle's bcpkix in the launched process, so against the binary it proves
 * that the native image carries everything bcpkix needs — the known risk of this service, which a
 * green JVM suite cannot see.
 *
 * <p>It is also this repository's <b>userflow catalogue</b>: the story's documentation is written
 * under {@code service/target/userstories/}, which the java-service release recipe requires and
 * publishes as {@code @userflows/qits-certificates}.
 */
@QuarkusIntegrationTest
@TestProfile(CertificatesBootstrapIT.PackagedWithMockIdp.class)
public class CertificatesBootstrapIT {

  static final String CATEGORY = "bootstrap";

  static final String SLUG = "the-certificate-authority-starts-with-a-working-crypto-path";

  static final String SERVICE = "qits-certificates";

  /**
   * The packaged process's environment: the gate on, the idp moved to the mock, telemetry dark.
   * Every key is a RUNTIME key: a packaged artifact takes its configuration as {@code -D}
   * arguments.
   */
  public static class PackagedWithMockIdp implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
      MockIdp idp = MockIdp.ensureStarted();
      Map<String, String> overrides = new LinkedHashMap<>();
      overrides.put("qits.auth.machine.required", "true");
      overrides.put("quarkus.oidc.auth-server-url", idp.baseUrl());
      overrides.put("quarkus.otel.sdk.disabled", "true");
      return overrides;
    }
  }

  /**
   * Every path is an edge, probes included: the shipped tap skips {@code /q/} paths, but until the
   * doors land (qits-2524 C2/C3) the readiness the deploy gates on IS this service's surface.
   */
  @BeforeAll
  static void tapTheNetwork() {
    NetworkTaps.restAssured(SERVICE, path -> false);
  }

  @UserStory(value = "The certificate authority starts with a working crypto path", category = CATEGORY)
  @UserStoryDescription(
      """
      qits-certificates holds the platform's trust anchors and signs leaf certificates. Before it
      reports ready it proves, in its own process, the whole crypto path it will use: it makes an
      EC P-384 anchor, self-signs it, and signs an EC P-256 certificate request end to end. The
      deploy gates on that readiness, so a container whose crypto is broken is never put in front
      of a caller.
      """)
  void theCertificateAuthorityStarts(Interactions story) {
    story.note("qits-certificates starts with the OIDC tenant on, beside a reachable qits-idp");
    NetworkCapture.actor("the deployer's health gate");
    given()
        .get("/certificates/q/health/ready")
        .then()
        .statusCode(200)
        .body("status", equalTo("UP"))
        .body("checks.find { it.name == 'certificates-crypto' }.status", equalTo("UP"))
        .body(
            "checks.find { it.name == 'certificates-crypto' }.data.anchorSubject",
            equalTo("CN=qits certificates smoke anchor,O=qits"))
        .body(
            "checks.find { it.name == 'certificates-crypto' }.data.leafSubject",
            equalTo("CN=smoke.certificates.invalid"))
        .body(not(containsString("PRIVATE KEY")));
    story.note("readiness is UP: an anchor was made and a CSR signed").as("crypto-ready");

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
    ReportAssertions.assertStepId(CATEGORY, SLUG, "live");
  }
}
