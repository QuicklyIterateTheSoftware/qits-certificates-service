package eu.wohlben.qits.certificates.health;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.containsString;

import eu.wohlben.qits.certificates.control.CertificateSmoke;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

/** The readiness the deploy gates on, with the crypto check in it, in the JVM. */
@QuarkusTest
class CryptoReadinessTest {

  @Test
  void readinessIsUpOnceACsrWasSignedEndToEnd() {
    given()
        .get("/certificates/q/health/ready")
        .then()
        .statusCode(200)
        .body("status", equalTo("UP"))
        .body("checks.find { it.name == 'certificates-crypto' }.status", equalTo("UP"))
        .body(
            "checks.find { it.name == 'certificates-crypto' }.data.leafSubject",
            equalTo("CN=" + CertificateSmoke.LEAF_NAME))
        .body(not(containsString("PRIVATE KEY")));
  }

  @Test
  void livenessIsTheDefault() {
    given().get("/certificates/q/health/live").then().statusCode(200).body("status", equalTo("UP"));
  }
}
