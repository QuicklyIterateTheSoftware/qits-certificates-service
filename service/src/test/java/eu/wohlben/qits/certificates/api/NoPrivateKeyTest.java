package eu.wohlben.qits.certificates.api;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.certificates.control.Anchors;
import eu.wohlben.qits.certificates.support.Ca;
import eu.wohlben.qits.certificates.support.ContractCallers;
import eu.wohlben.qits.certificates.support.Csrs;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.jboss.logmanager.ExtLogRecord;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * <b>No door, log line, health check or error body carries a {@code PRIVATE KEY}.</b> Every door
 * is called on every path it has, error paths included (304, 400, 401, 403, 405, 409, 500, 503,
 * 404), the leaf door's issuance and every refusal among them, plus
 * health and the API document; every body and every header is scanned, and so is every log record
 * the service writes meanwhile — including those about an anchor directory whose files hold a
 * private key where a certificate belongs.
 */
@QuarkusTest
class NoPrivateKeyTest {

  static final String MARK = "PRIVATE KEY";

  static final String ANCHORS = "/certificates/api/anchors";

  static final String LEAVES = "/certificates/api/leaves";

  @Inject Ca ca;

  @Inject Anchors anchors;

  private final List<String> logged = Collections.synchronizedList(new ArrayList<>());

  private final Handler capture =
      new Handler() {
        @Override
        public void publish(LogRecord record) {
          StringBuilder line = new StringBuilder();
          line.append(
              record instanceof ExtLogRecord ext ? ext.getFormattedMessage() : record.getMessage());
          if (record.getParameters() != null) {
            for (Object parameter : record.getParameters()) {
              line.append(' ').append(parameter);
            }
          }
          if (record.getThrown() != null) {
            StringWriter trace = new StringWriter();
            record.getThrown().printStackTrace(new PrintWriter(trace));
            line.append('\n').append(trace);
          }
          logged.add(line.toString());
        }

        @Override
        public void flush() {}

        @Override
        public void close() {}
      };

  @BeforeEach
  void listen() {
    capture.setLevel(Level.ALL);
    Logger.getLogger("").addHandler(capture);
  }

  @AfterEach
  void stop() {
    Logger.getLogger("").removeHandler(capture);
    ca.boot();
  }

  private final List<String> calls = new ArrayList<>();

  private void scan(String what, Supplier<Response> call, int status) {
    Response answer = call.get();
    calls.add(what);
    assertEquals(status, answer.statusCode(), what + " answered " + answer.asString());
    assertFalse(answer.asString().contains(MARK), what + " answered a private key");
    answer
        .getHeaders()
        .forEach(h -> assertFalse(h.getValue().contains(MARK), what + " header " + h.getName()));
  }

  @Test
  void noDoorNoLogLineAndNoErrorBodyCarriesAPrivateKey() throws Exception {
    String admin = ContractCallers.caller("operator", Roles.ADMIN);

    // A first boot, logged.
    ca.boot();
    Path key = anchors.bundle().anchors().get(0).directory().resolve("key.pem");
    assertTrue(Files.readString(key).contains(MARK), "the volume does hold the key");

    // Corrupt directories whose files hold a private key where they should not: logged, ignored.
    Path wrong = Files.createDirectory(ca.directory().resolve("key-as-cert"));
    Files.copy(key, wrong.resolve("cert.pem"));
    Files.copy(key, wrong.resolve("key.pem"));
    Files.writeString(
        wrong.resolve("state.json"),
        "{\"id\":\"key-as-cert\",\"status\":\"ACTIVE\",\"createdAt\":\"2026-11-01T00:00:00Z\","
            + "\"activatesAt\":\"2026-11-01T00:00:00Z\",\"notAfter\":\"2031-11-01T00:00:00Z\","
            + "\"sha256\":\"00\"}");
    Path keyAsState = Files.createDirectory(ca.directory().resolve("key-as-state"));
    Files.copy(key, keyAsState.resolve("state.json"));
    anchors.load();
    assertEquals(1, anchors.all().size());

    scan("GET anchors", () -> given().get(ANCHORS), 200);
    scan("GET anchors PEM", () -> given().header("Accept", "application/x-pem-file").get(ANCHORS), 200);
    scan("GET anchors JSON", () -> given().header("Accept", "application/json").get(ANCHORS), 200);
    String etag = given().get(ANCHORS).getHeader("ETag");
    scan("GET anchors 304", () -> given().header("If-None-Match", etag).get(ANCHORS), 304);
    scan("GET anchors 406", () -> given().header("Accept", "image/png").get(ANCHORS), 406);
    scan("POST rotate anonymous", () -> given().post(ANCHORS + "/rotate"), 401);
    scan(
        "POST rotate as agent",
        () -> given().header("Authorization", ContractCallers.caller("a", "qits:agent")).post(ANCHORS + "/rotate"),
        403);
    scan("POST rotate", () -> given().header("Authorization", admin).post(ANCHORS + "/rotate"), 201);
    scan("POST rotate again", () -> given().header("Authorization", admin).post(ANCHORS + "/rotate"), 409);
    scan("GET anchors JSON with PENDING", () -> given().header("Accept", "application/json").get(ANCHORS), 200);
    scan("GET rotate", () -> given().get(ANCHORS + "/rotate"), 405);

    // The leaf door: issued, and every refusal. It signs with the key the volume holds.
    String requester = ContractCallers.caller("dev-qits-egress", Roles.SYSTEM);
    String csr = Csrs.body(Csrs.fixture(Csrs.TWO_NAMES));
    String p384 = Csrs.body(Csrs.forNames(Csrs.keys("EC", "secp384r1"), "a.example.org"));
    scan("POST leaves anonymous", () -> leaf(null, csr), 401);
    scan("POST leaves as agent", () -> leaf(ContractCallers.caller("a", "qits:agent"), csr), 403);
    scan(
        "POST leaves as a non-requester",
        () -> leaf(ContractCallers.caller("dev-qits-ci", Roles.SYSTEM), csr),
        403);
    scan("POST leaves", () -> leaf(requester, csr), 201);
    scan(
        "POST leaves name refused",
        () -> leaf(requester, Csrs.body(Csrs.fixture(Csrs.INTERNAL_NAME))),
        400);
    scan(
        "POST leaves with a P-384 key",
        () -> leaf(requester, p384),
        400);
    // A private key where the CSR belongs: refused, and never echoed.
    String keyAsCsr = Csrs.body(Files.readString(key));
    scan("POST leaves with a key for a CSR", () -> leaf(requester, keyAsCsr), 400);
    scan("POST leaves with no csr", () -> leaf(requester, "{}"), 400);
    scan("GET leaves", () -> given().get(LEAVES), 405);

    // The workload door (qits-2756): issued, and every refusal.
    String edge =
        ContractCallers.token(
            java.util.Map.of(
                "sub", "dev-qits-edge",
                "groups", java.util.List.of(Roles.SYSTEM, "clients/dev-qits-edge")),
            Roles.SYSTEM);
    String person =
        ContractCallers.token(
            java.util.Map.of("sub", "p", "credential_type", "cli"), Roles.ADMIN);
    scan("POST workload anonymous", () -> workload(null, csr), 401);
    scan("POST workload as a person", () -> workload(person, csr), 403);
    scan("POST workload", () -> workload(edge, csr), 201);
    scan("POST workload with a P-384 key", () -> workload(edge, p384), 400);
    scan("POST workload with a key for a CSR", () -> workload(edge, keyAsCsr), 400);
    scan("POST workload with no csr", () -> workload(edge, "{}"), 400);
    scan("GET unknown", () -> given().get("/certificates/api/nothing"), 404);
    scan("GET ready", () -> given().get("/certificates/q/health/ready"), 200);
    scan("GET live", () -> given().get("/certificates/q/health/live"), 200);
    scan("GET health", () -> given().get("/certificates/q/health"), 200);
    scan("GET openapi", () -> given().get("/certificates/q/openapi"), 200);

    // The volume refuses the write: 500, and its log line.
    ca.stage(Ca.ACTIVE);
    Path dir = ca.directory();
    Path aside = dir.resolveSibling("anchors-aside");
    Files.move(dir, aside);
    Files.writeString(dir, "a file where the anchors directory belongs");
    try {
      scan("POST rotate on a broken volume", () -> given().header("Authorization", admin).post(ANCHORS + "/rotate"), 500);
    } finally {
      Files.delete(dir);
      Files.move(aside, dir);
    }

    // The ACTIVE anchor's key is gone from the volume: the leaf door's 500, and its log line.
    ca.stage(Ca.ACTIVE);
    Files.delete(ca.directory().resolve(Ca.ACTIVE).resolve("key.pem"));
    scan("POST leaves with an unreadable key", () -> leaf(requester, csr), 500);

    // No anchor at all: 503, and readiness DOWN.
    ca.empty();
    scan("POST leaves with none", () -> leaf(requester, csr), 503);
    scan("GET anchors with none", () -> given().get(ANCHORS), 503);
    scan("GET anchors JSON with none", () -> given().header("Accept", "application/json").get(ANCHORS), 503);
    scan("GET ready with none", () -> given().get("/certificates/q/health/ready"), 503);

    List<String> lines = List.copyOf(logged);
    assertTrue(
        lines.stream().anyMatch(l -> l.contains("key-as-cert") && l.contains("ignored")),
        "the corrupt directory was logged: " + lines);
    assertTrue(
        lines.stream().anyMatch(l -> l.contains("the anchor store failed")),
        "the volume fault was logged: " + lines);
    for (String line : lines) {
      assertFalse(line.contains(MARK), "a log line carries a private key: " + line);
    }
    assertTrue(
        lines.stream().anyMatch(l -> l.contains("certificates decision=ISSUED")),
        "the issuance was audited: " + lines);
    assertEquals(37, calls.size(), "every door and every path: " + calls);
  }

  private static Response leaf(String authorization, String body) {
    var request = given().contentType("application/json").body(body);
    if (authorization != null) {
      request = request.header("Authorization", authorization);
    }
    return request.post(LEAVES);
  }

  private static Response workload(String authorization, String body) {
    var request = given().contentType("application/json").body(body);
    if (authorization != null) {
      request = request.header("Authorization", authorization);
    }
    return request.post("/certificates/api/workload-certificates");
  }
}
