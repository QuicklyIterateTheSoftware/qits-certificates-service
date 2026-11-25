package eu.wohlben.qits.certificates.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import eu.wohlben.qits.certificates.control.Anchor;
import eu.wohlben.qits.certificates.control.Anchors;
import java.time.Instant;
import java.util.List;

/** The JSON on the wire. Every nested type is listed in {@link ApiWireReflection}. */
public final class AnchorsWire {

  private AnchorsWire() {}

  /**
   * One anchor, as the JSON bundle lists it and the rotate door answers it.
   *
   * @param subject {@code CN=qits platform CA <env> <yyyy-MM>, O=qits}
   * @param serial the serial number, lower-case hex
   * @param sha256 the lower-case hex SHA-256 of the certificate's DER encoding
   * @param retiresAt null until the anchor is RETIRING
   */
  public record AnchorDto(
      String id,
      String status,
      String subject,
      String serial,
      Instant notBefore,
      Instant notAfter,
      String sha256,
      Instant activatesAt,
      Instant retiresAt) {

    static AnchorDto of(Anchor anchor) {
      return new AnchorDto(
          anchor.id(),
          anchor.status().name(),
          anchor.subject(),
          anchor.serial(),
          anchor.notBefore(),
          anchor.notAfter(),
          anchor.state().sha256(),
          anchor.state().activatesAt(),
          anchor.state().retiresAt());
    }
  }

  /**
   * The published anchors, in bundle order (ACTIVE, PENDING, RETIRING).
   *
   * @param version the lower-case hex SHA-256 of the PEM bundle; also the {@code ETag}
   */
  public record AnchorsDto(String version, List<AnchorDto> anchors) {

    static AnchorsDto of(Anchors.Bundle bundle) {
      return new AnchorsDto(bundle.version(), bundle.anchors().stream().map(AnchorDto::of).toList());
    }
  }

  /** A refusal. {@code anchorId} names the PENDING anchor of a 409, and is absent otherwise. */
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record ErrorBody(String error, String anchorId) {

    ErrorBody(String error) {
      this(error, null);
    }
  }
}
