package eu.wohlben.qits.certificates.health;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;

import eu.wohlben.qits.certificates.support.Ca;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.nio.file.Files;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** The readiness the deploy gates on: one ACTIVE anchor, its key readable. */
@QuarkusTest
class AnchorsReadinessTest {

  static final String READY = "/certificates/q/health/ready";

  static final String CHECK = "checks.find { it.name == 'certificates-anchors' }";

  @Inject Ca ca;

  @AfterEach
  void restore() {
    ca.boot();
  }

  @Test
  void readyOnceTheFirstBootMadeItsActiveAnchor() {
    ca.boot();
    given()
        .get(READY)
        .then()
        .statusCode(200)
        .body("status", equalTo("UP"))
        .body(CHECK + ".status", equalTo("UP"))
        .body(CHECK + ".data.subject", equalTo("CN=qits platform CA dev " + java.time.YearMonth.now(java.time.ZoneOffset.UTC) + ", O=qits"))
        .body(CHECK + ".data.published", equalTo(1))
        .body(not(containsString("PRIVATE KEY")));
  }

  @Test
  void downWithNoAnchor() {
    ca.empty();
    given()
        .get(READY)
        .then()
        .statusCode(503)
        .body("status", equalTo("DOWN"))
        .body(CHECK + ".status", equalTo("DOWN"))
        .body(CHECK + ".data.reason", equalTo("0 ACTIVE anchors are loaded, not 1"));
  }

  @Test
  void downWhenTheActiveKeyIsGone() throws Exception {
    ca.stage(Ca.ACTIVE);
    given().get(READY).then().statusCode(200).body(CHECK + ".data.activeAnchor", equalTo(Ca.ACTIVE));
    Files.delete(ca.directory().resolve(Ca.ACTIVE).resolve("key.pem"));
    given().get(READY).then().statusCode(503).body(CHECK + ".status", equalTo("DOWN"));
  }

  @Test
  void livenessIsTheDefault() {
    given().get("/certificates/q/health/live").then().statusCode(200).body("status", equalTo("UP"));
  }
}
