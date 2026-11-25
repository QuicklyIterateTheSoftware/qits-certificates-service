package eu.wohlben.qits.certificates.contracts;

import static io.restassured.RestAssured.given;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import eu.wohlben.qits.certificates.support.ContractCallers;
import eu.wohlben.qits.certificates.support.Csrs;
import eu.wohlben.qits.certificates.support.TestClock;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * <b>Records qits-certificates' provider golden masters</b> — {@code golden-masters/} at the
 * repository root, the source of {@code eu.wohlben.qits:qits-certificates-golden-masters}. The
 * machinery is qits-agents-service's.
 *
 * <p>For each (state, operation) pair in {@link #INTERACTIONS} it runs the state ({@link
 * ProviderStates}), calls the operation with {@code Accept: application/json}, freezes ids and
 * instants ({@link Freezer}) and renders {@code golden-masters/<state-slug>/<operationId>.json};
 * then {@code golden-masters/index.json} (format version 1). The anchors read is recorded with its
 * {@code ETag} in {@code responseHeaders}, so a consumer polling with {@code If-None-Match} can pin
 * that it reads one.
 *
 * <p><b>Deterministic by construction.</b> The states stage the fixed fixture anchors with the
 * clock pinned, so the bundle, its version and every certificate field are the same bytes on every
 * run. The leaf states also pin the leaf's randomness and send a fixed fixture CSR, so an issued
 * leaf, its serial and its signature are the same bytes too. The one answer that cannot be is a
 * new anchor's (the rotation's 201): its key, and so its
 * {@code serial} and {@code sha256}, are random. Those two values are frozen as unique tokens
 * ({@code frozen.strings}), which a consumer matches by type.
 *
 * <p>The release gate fails any operation of {@code docs/openapi.yml} this table does not cover, so
 * a new door joins it in the same commit.
 *
 * <p>It <b>compares by default</b> and fails with a unified diff per differing file, including a
 * committed {@code .json} no interaction produces any more; {@code -Dgolden.update=true} rewrites.
 */
@QuarkusTest
class GoldenMasterRecordingTest {

  static final int FORMAT_VERSION = 1;

  static final String PROVIDER = "qits-certificates";

  static final String API = "/certificates/api";

  /**
   * One recorded interaction; {@code requestBody} the JSON it sends (recorded in the index as the
   * operation's {@code body}), or null; {@code authorized} whether it calls as the state's caller
   * ({@link ProviderStates.Setup#caller()}, sent and not recorded) rather than anonymously; {@code
   * responseHeaders} the answer's headers recorded, and {@code randomFields} the top-level answer
   * fields that hold freshly random values.
   */
  record Interaction(
      String state,
      String operationId,
      String method,
      String path,
      String requestBody,
      int status,
      boolean authorized,
      List<String> responseHeaders,
      List<String> randomFields) {}

  static final List<Interaction> INTERACTIONS =
      List.of(
          new Interaction(
              ProviderStates.ONE_ACTIVE_ANCHOR,
              "getAnchors",
              "GET",
              API + "/anchors",
              null,
              200,
              false,
              List.of("ETag"),
              List.of()),
          new Interaction(
              ProviderStates.ONE_ACTIVE_ANCHOR,
              "rotateAnchors",
              "POST",
              API + "/anchors/rotate",
              null,
              201,
              true,
              List.of(),
              List.of("serial", "sha256")),
          new Interaction(
              ProviderStates.ONE_ACTIVE_AND_ONE_PENDING_ANCHOR,
              "getAnchors",
              "GET",
              API + "/anchors",
              null,
              200,
              false,
              List.of("ETag"),
              List.of()),
          new Interaction(
              ProviderStates.ONE_ACTIVE_AND_ONE_PENDING_ANCHOR,
              "rotateAnchors",
              "POST",
              API + "/anchors/rotate",
              null,
              409,
              true,
              List.of(),
              List.of()),
          new Interaction(
              ProviderStates.LEAF_ISSUED,
              "issueLeaf",
              "POST",
              API + "/leaves",
              Csrs.body(Csrs.fixture(Csrs.TWO_NAMES)),
              201,
              true,
              List.of(),
              List.of()),
          new Interaction(
              ProviderStates.LEAF_NAME_REFUSED,
              "issueLeaf",
              "POST",
              API + "/leaves",
              Csrs.body(Csrs.fixture(Csrs.INTERNAL_NAME)),
              400,
              true,
              List.of(),
              List.of()),
          new Interaction(
              ProviderStates.NOT_A_LEAF_REQUESTER,
              "issueLeaf",
              "POST",
              API + "/leaves",
              Csrs.body(Csrs.fixture(Csrs.TWO_NAMES)),
              403,
              true,
              List.of(),
              List.of()));

  private static final ObjectMapper JSON = new ObjectMapper();

  private static final Pattern TEMPLATE_PARAM = Pattern.compile("\\{([^}]+)}");

  @Inject ProviderStates states;

  @Inject TestClock clock;

  @AfterEach
  void unpin() {
    clock.reset();
    states.reset();
  }

  @Test
  void goldenMastersMatchTheProvider() throws IOException {
    Path dir = GoldenFiles.repositoryRoot().resolve("golden-masters");
    boolean update = GoldenFiles.updating();
    List<String> failures = new ArrayList<>();
    Set<String> written = new TreeSet<>();
    Map<String, ObjectNode> indexStates = new TreeMap<>();
    Map<String, Map<String, ObjectNode>> indexOperations = new TreeMap<>();
    Map<String, Map<String, String>> committed = committedParams(dir.resolve("index.json"));

    for (Interaction interaction : INTERACTIONS) {
      String slug = ProviderStates.slug(interaction.state());
      ProviderStates.Setup setup = states.setUp(interaction.state());
      Recorded recorded = record(interaction, setup, committed.getOrDefault(slug, Map.of()));
      String file = slug + "/" + interaction.operationId() + ".json";

      ObjectNode state = indexStates.get(slug);
      if (state == null) {
        state = JsonNodeFactory.instance.objectNode();
        state.put("name", interaction.state());
        state.put("slug", slug);
        state.set("params", recorded.params());
        state.set("dependsOn", JsonNodeFactory.instance.arrayNode());
        indexStates.put(slug, state);
      } else if (!state.get("params").equals(recorded.params())) {
        failures.add("State '" + interaction.state() + "' froze to different params per operation");
      }

      ObjectNode operation = JsonNodeFactory.instance.objectNode();
      operation.put("operationId", interaction.operationId());
      operation.put("method", interaction.method());
      operation.put("path", interaction.path());
      if (interaction.requestBody() != null) {
        operation.set("body", JSON.readTree(interaction.requestBody()));
      }
      operation.put("status", interaction.status());
      if (!recorded.headers().isEmpty()) {
        ObjectNode headers = operation.putObject("responseHeaders");
        recorded.headers().forEach(headers::put);
      }
      operation.put("file", file);
      ObjectNode frozen = operation.putObject("frozen");
      frozen.set("ids", strings(recorded.freezer().idPaths()));
      frozen.set("instants", strings(recorded.freezer().instantPaths()));
      frozen.set("strings", strings(recorded.freezer().stringPaths()));
      frozen.putNull("listFilteredTo");
      if (indexOperations
              .computeIfAbsent(slug, k -> new TreeMap<>())
              .put(interaction.operationId(), operation)
          != null) {
        failures.add("Duplicate interaction " + file);
      }
      written.add(file);
      check(dir.resolve(file), GoldenJson.render(recorded.body()), update, failures);
    }

    ObjectNode index = JsonNodeFactory.instance.objectNode();
    index.put("formatVersion", FORMAT_VERSION);
    index.put("provider", PROVIDER);
    ArrayNode stateArray = index.putArray("states");
    indexStates.forEach(
        (slug, state) -> {
          ArrayNode operations = state.putArray("operations");
          indexOperations.get(slug).values().forEach(operations::add);
          stateArray.add(state);
        });
    written.add("index.json");
    check(dir.resolve("index.json"), GoldenJson.render(index), update, failures);

    for (String stale : committedJson(dir)) {
      if (written.contains(stale)) {
        continue;
      }
      if (update) {
        Files.delete(dir.resolve(stale));
      } else {
        failures.add(
            dir.resolve(stale)
                + " is committed but no interaction records it any more — rerun with"
                + " -Dgolden.update=true to delete it.");
      }
    }
    if (!failures.isEmpty()) {
      throw new AssertionError(String.join("\n\n", failures));
    }
  }

  /** One interaction's frozen answer, its frozen params, its headers and what was frozen where. */
  record Recorded(JsonNode body, ObjectNode params, Map<String, String> headers, Freezer freezer) {}

  private static Recorded record(
      Interaction interaction, ProviderStates.Setup setup, Map<String, String> committedParams)
      throws IOException {
    Map<String, String> params = setup.params();
    var request = given().header("Accept", "application/json");
    if (interaction.authorized()) {
      ProviderStates.Caller caller = setup.caller();
      request =
          request.header(
              "Authorization",
              ContractCallers.caller(caller.subject(), caller.roles().toArray(String[]::new)));
    }
    if (interaction.requestBody() != null) {
      request = request.contentType("application/json").body(interaction.requestBody());
    }
    Response response =
        request.when().request(interaction.method(), expand(interaction.path(), params));
    String raw = response.asString();
    if (response.statusCode() != interaction.status()) {
      throw new AssertionError(
          interaction.method()
              + " "
              + interaction.path()
              + " in state '"
              + interaction.state()
              + "' answered "
              + response.statusCode()
              + ", expected "
              + interaction.status()
              + ": "
              + raw);
    }
    JsonNode body = raw.isEmpty() ? JsonNodeFactory.instance.nullNode() : JSON.readTree(raw);
    List<String> random = new ArrayList<>();
    for (String field : interaction.randomFields()) {
      JsonNode value = body.get(field);
      if (value == null || !value.isTextual() || value.asText().isEmpty()) {
        throw new AssertionError(interaction.operationId() + " answered no " + field + ": " + raw);
      }
      random.add(value.asText());
    }
    Map<String, String> headers = new TreeMap<>();
    for (String name : interaction.responseHeaders()) {
      String value = response.getHeader(name);
      if (value == null) {
        throw new AssertionError(interaction.operationId() + " answered no " + name + " header");
      }
      headers.put(name, value);
    }
    Freezer freezer = new Freezer().seed(params, committedParams).uniqueTokens(random);
    ObjectNode frozenParams = JsonNodeFactory.instance.objectNode();
    params.forEach((k, v) -> frozenParams.put(k, freezer.freezeParam(v)));
    return new Recorded(freezer.freeze(body), frozenParams, headers, freezer);
  }

  private static void check(Path golden, String actual, boolean update, List<String> failures) {
    String failure = GoldenFiles.check(golden, actual, update, UnaryOperator.identity());
    if (failure != null) {
      failures.add(failure);
    }
  }

  private static String expand(String template, Map<String, String> params) {
    Matcher m = TEMPLATE_PARAM.matcher(template);
    StringBuilder out = new StringBuilder();
    while (m.find()) {
      String value = params.get(m.group(1));
      if (value == null) {
        throw new IllegalStateException(
            "Path " + template + " names {" + m.group(1) + "}, which the state does not return");
      }
      m.appendReplacement(out, Matcher.quoteReplacement(value));
    }
    m.appendTail(out);
    return out.toString();
  }

  private static ArrayNode strings(List<String> values) {
    ArrayNode out = JsonNodeFactory.instance.arrayNode();
    values.forEach(out::add);
    return out;
  }

  /** slug → frozen params of every state in the committed index; empty when there is none yet. */
  static Map<String, Map<String, String>> committedParams(Path index) throws IOException {
    if (!Files.isRegularFile(index)) {
      return Map.of();
    }
    Map<String, Map<String, String>> out = new TreeMap<>();
    for (JsonNode state : JSON.readTree(index.toFile()).path("states")) {
      Map<String, String> params = new TreeMap<>();
      state
          .path("params")
          .properties()
          .forEach(p -> params.put(p.getKey(), p.getValue().asText()));
      out.put(state.path("slug").asText(), params);
    }
    return out;
  }

  private static List<String> committedJson(Path dir) throws IOException {
    if (!Files.isDirectory(dir)) {
      return List.of();
    }
    try (Stream<Path> files = Files.walk(dir)) {
      return files
          .filter(Files::isRegularFile)
          .filter(p -> p.getFileName().toString().endsWith(".json"))
          .map(p -> dir.relativize(p).toString().replace('\\', '/'))
          .sorted()
          .toList();
    }
  }
}
