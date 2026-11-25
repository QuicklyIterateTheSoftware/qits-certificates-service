package eu.wohlben.qits.certificates.control;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.time.Instant;
import java.util.Objects;

/**
 * An anchor's {@code state.json}: {@code {"id","status","createdAt","activatesAt","retiresAt",
 * "notAfter","sha256"}}, instants as ISO-8601, {@code retiresAt} null until the anchor is RETIRING.
 *
 * <p>Read and written through Jackson's tree model, never by reflection, so the native image needs
 * no registration for it.
 *
 * @param sha256 the lower-case hex SHA-256 of the certificate's DER encoding
 */
public record AnchorState(
    String id,
    AnchorStatus status,
    Instant createdAt,
    Instant activatesAt,
    Instant retiresAt,
    Instant notAfter,
    String sha256) {

  private static final ObjectMapper JSON = new ObjectMapper();

  public AnchorState {
    Objects.requireNonNull(id, "id");
    Objects.requireNonNull(status, "status");
    Objects.requireNonNull(createdAt, "createdAt");
    Objects.requireNonNull(activatesAt, "activatesAt");
    Objects.requireNonNull(notAfter, "notAfter");
    Objects.requireNonNull(sha256, "sha256");
  }

  public AnchorState withStatus(AnchorStatus next) {
    return new AnchorState(id, next, createdAt, activatesAt, retiresAt, notAfter, sha256);
  }

  public AnchorState activated(Instant at) {
    return new AnchorState(id, AnchorStatus.ACTIVE, createdAt, at, retiresAt, notAfter, sha256);
  }

  public AnchorState retiring(Instant until) {
    return new AnchorState(id, AnchorStatus.RETIRING, createdAt, activatesAt, until, notAfter, sha256);
  }

  /** The file's content, one key per line, with a trailing newline. */
  public String toJson() {
    ObjectNode node = JSON.createObjectNode();
    node.put("id", id);
    node.put("status", status.name());
    node.put("createdAt", createdAt.toString());
    node.put("activatesAt", activatesAt.toString());
    if (retiresAt == null) {
      node.putNull("retiresAt");
    } else {
      node.put("retiresAt", retiresAt.toString());
    }
    node.put("notAfter", notAfter.toString());
    node.put("sha256", sha256);
    try {
      return JSON.writerWithDefaultPrettyPrinter().writeValueAsString(node) + "\n";
    } catch (IOException e) {
      throw new IllegalStateException("state.json did not render", e);
    }
  }

  /**
   * Parses a {@code state.json}.
   *
   * @throws IllegalArgumentException naming the first field that is missing or malformed
   */
  public static AnchorState parse(String json) {
    JsonNode node;
    try {
      node = JSON.readTree(json);
    } catch (IOException e) {
      throw new IllegalArgumentException("state.json is not JSON");
    }
    if (node == null || !node.isObject()) {
      throw new IllegalArgumentException("state.json is not a JSON object");
    }
    String status = text(node, "status", true);
    AnchorStatus parsed;
    try {
      parsed = AnchorStatus.valueOf(status);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("state.json has an unknown status " + status);
    }
    return new AnchorState(
        text(node, "id", true),
        parsed,
        instant(node, "createdAt", true),
        instant(node, "activatesAt", true),
        instant(node, "retiresAt", false),
        instant(node, "notAfter", true),
        text(node, "sha256", true));
  }

  private static String text(JsonNode node, String field, boolean required) {
    JsonNode value = node.get(field);
    if (value == null || value.isNull()) {
      if (required) {
        throw new IllegalArgumentException("state.json has no " + field);
      }
      return null;
    }
    if (!value.isTextual()) {
      throw new IllegalArgumentException("state.json's " + field + " is not a string");
    }
    return value.asText();
  }

  private static Instant instant(JsonNode node, String field, boolean required) {
    String value = text(node, field, required);
    if (value == null) {
      return null;
    }
    try {
      return Instant.parse(value);
    } catch (RuntimeException e) {
      throw new IllegalArgumentException("state.json's " + field + " is not an instant");
    }
  }
}
