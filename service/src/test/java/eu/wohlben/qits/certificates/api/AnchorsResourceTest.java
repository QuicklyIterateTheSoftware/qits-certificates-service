package eu.wohlben.qits.certificates.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import eu.wohlben.qits.certificates.control.AnchorCrypto;
import eu.wohlben.qits.certificates.control.Anchors;
import eu.wohlben.qits.certificates.support.Ca;
import eu.wohlben.qits.certificates.support.ContractCallers;
import eu.wohlben.qits.certificates.support.TestClock;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** The anchors doors, over the staged fixture anchors and the suite's clock. */
@QuarkusTest
class AnchorsResourceTest {

  static final String ANCHORS = "/certificates/api/anchors";

  static final String ROTATE = ANCHORS + "/rotate";

  @Inject Ca ca;

  @Inject TestClock clock;

  @Inject Anchors anchors;

  @AfterEach
  void unpin() {
    clock.reset();
  }

  static String pem(String id) throws Exception {
    Path cert =
        Path.of(AnchorsResourceTest.class.getClassLoader().getResource("fixtures/anchors").toURI())
            .resolve(id)
            .resolve("cert.pem");
    return Files.readString(cert, StandardCharsets.US_ASCII);
  }

  static List<X509Certificate> certificates(String pem) throws Exception {
    return CertificateFactory.getInstance("X.509")
        .generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)))
        .stream()
        .map(X509Certificate.class::cast)
        .toList();
  }

  static String version(String bundle) {
    return AnchorCrypto.sha256(bundle.getBytes(StandardCharsets.US_ASCII));
  }

  @Test
  void theDefaultAnswerIsThePemBundleWithItsVersionAsETag() throws Exception {
    ca.stage(Ca.ACTIVE);
    String bundle = pem(Ca.ACTIVE);

    Response answer = given().get(ANCHORS);
    answer.then().statusCode(200).contentType(startsWith("text/plain"));
    assertEquals(bundle, answer.asString());
    assertEquals("\"" + version(bundle) + "\"", answer.getHeader("ETag"));
    assertEquals(1, certificates(answer.asString()).size());
    assertEquals(0, certificates(answer.asString()).get(0).getBasicConstraints(), "CA:TRUE");

    given()
        .header("Accept", "application/x-pem-file")
        .get(ANCHORS)
        .then()
        .statusCode(200)
        .contentType(startsWith("application/x-pem-file"))
        .header("ETag", "\"" + version(bundle) + "\"")
        .body(equalTo(bundle));
    given().header("Accept", "text/plain").get(ANCHORS).then().statusCode(200).body(equalTo(bundle));
  }

  @Test
  void jsonListsEachAnchorWithTheBundleVersion() throws Exception {
    ca.stage(Ca.ACTIVE, Ca.PENDING);
    String bundle = pem(Ca.ACTIVE) + pem(Ca.PENDING);
    X509Certificate active = certificates(pem(Ca.ACTIVE)).get(0);

    given()
        .header("Accept", "application/json")
        .get(ANCHORS)
        .then()
        .statusCode(200)
        .contentType(startsWith("application/json"))
        .header("ETag", "\"" + version(bundle) + "\"")
        .body("version", equalTo(version(bundle)))
        .body("anchors", hasSize(2))
        .body("anchors[0].id", equalTo(Ca.ACTIVE))
        .body("anchors[0].status", equalTo("ACTIVE"))
        .body("anchors[0].subject", equalTo("CN=qits platform CA dev 2026-11, O=qits"))
        .body("anchors[0].serial", equalTo(active.getSerialNumber().toString(16)))
        .body("anchors[0].notBefore", equalTo("2026-10-31T23:55:00Z"))
        .body("anchors[0].notAfter", equalTo("2031-11-01T00:00:00Z"))
        .body("anchors[0].sha256", equalTo(AnchorCrypto.sha256(active)))
        .body("anchors[0].activatesAt", equalTo("2026-11-01T00:00:00Z"))
        .body("anchors[0].retiresAt", nullValue())
        .body("anchors[1].id", equalTo(Ca.PENDING))
        .body("anchors[1].status", equalTo("PENDING"))
        .body("anchors[1].activatesAt", equalTo("2026-12-20T00:00:00Z"));
  }

  @Test
  void theBundleFollowsEveryState() throws Exception {
    ca.stage(Ca.ACTIVE, Ca.PENDING);
    assertEquals(pem(Ca.ACTIVE) + pem(Ca.PENDING), given().get(ANCHORS).asString(), "ACTIVE + PENDING");

    // The PENDING anchor activates: it comes first, the old one is RETIRING and still published.
    clock.set(Instant.parse("2026-12-20T00:00:00Z"));
    anchors.tick();
    assertEquals(pem(Ca.PENDING) + pem(Ca.ACTIVE), given().get(ANCHORS).asString(), "ACTIVE + RETIRING");
    given()
        .header("Accept", "application/json")
        .get(ANCHORS)
        .then()
        .body("anchors[0].status", equalTo("ACTIVE"))
        .body("anchors[0].id", equalTo(Ca.PENDING))
        .body("anchors[1].status", equalTo("RETIRING"))
        .body("anchors[1].retiresAt", equalTo("2026-12-28T00:00:00Z"));

    // Retired: out of the bundle, its key gone, its certificate kept.
    clock.advance(Duration.ofDays(8));
    anchors.tick();
    assertEquals(pem(Ca.PENDING), given().get(ANCHORS).asString(), "ACTIVE alone");
    assertEquals(false, Files.exists(ca.directory().resolve(Ca.ACTIVE).resolve("key.pem")));
    assertEquals(true, Files.exists(ca.directory().resolve(Ca.ACTIVE).resolve("cert.pem")));
  }

  @Test
  void ifNoneMatchWithTheVersionIsNotModified() throws Exception {
    ca.stage(Ca.ACTIVE);
    String etag = given().get(ANCHORS).getHeader("ETag");

    given()
        .header("If-None-Match", etag)
        .get(ANCHORS)
        .then()
        .statusCode(304)
        .header("ETag", etag)
        .body(emptyString());
    given()
        .header("Accept", "application/json")
        .header("If-None-Match", etag)
        .get(ANCHORS)
        .then()
        .statusCode(304);
    given().header("If-None-Match", "\"stale\"").get(ANCHORS).then().statusCode(200);

    // A rotation changes the version, and the old ETag no longer matches.
    anchors.rotate();
    given().header("If-None-Match", etag).get(ANCHORS).then().statusCode(200);
  }

  @Test
  void rotateMakesAPendingAnchorOnceAndOnlyForAnAdmin() throws Exception {
    ca.stage(Ca.ACTIVE);
    String admin = ContractCallers.caller("operator", Roles.ADMIN);

    given().post(ROTATE).then().statusCode(401);
    given()
        .header("Authorization", ContractCallers.caller("someone", "qits:agent"))
        .post(ROTATE)
        .then()
        .statusCode(403);

    String id =
        given()
            .header("Authorization", admin)
            .post(ROTATE)
            .then()
            .statusCode(201)
            .contentType(startsWith("application/json"))
            .body("status", equalTo("PENDING"))
            .body("subject", equalTo("CN=qits platform CA dev 2026-11, O=qits"))
            .body("activatesAt", equalTo("2026-12-25T12:00:00Z"))
            .body("retiresAt", nullValue())
            .extract()
            .path("id");

    given()
        .header("Authorization", admin)
        .post(ROTATE)
        .then()
        .statusCode(409)
        .body("error", equalTo("an anchor is already PENDING"))
        .body("anchorId", equalTo(id));

    List<X509Certificate> published = certificates(given().get(ANCHORS).asString());
    assertEquals(2, published.size());
    assertArrayEquals(certificates(pem(Ca.ACTIVE)).get(0).getEncoded(), published.get(0).getEncoded());
  }

  @Test
  void noAnchorIsServiceUnavailable() {
    ca.empty();
    given().get(ANCHORS).then().statusCode(503).body(not(containsString("PRIVATE KEY")));
    given()
        .header("Accept", "application/json")
        .get(ANCHORS)
        .then()
        .statusCode(503)
        .body("error", equalTo("no anchor is loaded"));
    ca.boot();
  }
}
