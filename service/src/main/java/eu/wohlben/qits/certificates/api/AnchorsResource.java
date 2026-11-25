package eu.wohlben.qits.certificates.api;

import eu.wohlben.qits.certificates.api.AnchorsWire.AnchorDto;
import eu.wohlben.qits.certificates.api.AnchorsWire.AnchorsDto;
import eu.wohlben.qits.certificates.api.AnchorsWire.ErrorBody;
import eu.wohlben.qits.certificates.control.Anchor;
import eu.wohlben.qits.certificates.control.Anchors;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.EntityTag;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Request;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.enums.SchemaType;
import org.eclipse.microprofile.openapi.annotations.headers.Header;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.jboss.logging.Logger;

/**
 * The trust anchors, {@code /anchors}.
 *
 * <ul>
 *   <li>{@code GET /anchors}, {@code @PermitAll}: the PEM bundle (every PENDING, ACTIVE and
 *       RETIRING certificate, ACTIVE first) as {@code text/plain}, the default, or {@code
 *       application/x-pem-file}; with {@code Accept: application/json}, {@link AnchorsDto}. Both
 *       carry {@code ETag: "<version>"}, the SHA-256 of the PEM bundle, and an {@code
 *       If-None-Match} naming it answers 304.
 *   <li>{@code POST /anchors/rotate}, {@code qits:admin}: a new PENDING anchor (201, {@link
 *       AnchorDto}), or 409 while one is PENDING.
 * </ul>
 *
 * <p>No answer here ever carries a private key: the bundle is built from {@code cert.pem} alone.
 */
@Path("/anchors")
public class AnchorsResource {

  /** The PEM media type a client may ask for by name. */
  static final String PEM = "application/x-pem-file";

  private static final Logger LOG = Logger.getLogger(AnchorsResource.class);

  @Inject Anchors anchors;

  @GET
  @PermitAll
  @Produces({MediaType.TEXT_PLAIN, PEM, MediaType.APPLICATION_JSON})
  @Operation(
      operationId = "getAnchors",
      summary = "The trust anchors: the PEM bundle, or JSON with Accept: application/json")
  @APIResponse(
      responseCode = "200",
      description =
          "Every PENDING, ACTIVE and RETIRING anchor, ACTIVE first. The PEM bundle by default;"
              + " ETag is the SHA-256 of the PEM bundle in either form",
      headers = @Header(name = "ETag", schema = @Schema(type = SchemaType.STRING)),
      content = {
        @Content(mediaType = MediaType.TEXT_PLAIN, schema = @Schema(type = SchemaType.STRING)),
        @Content(mediaType = PEM, schema = @Schema(type = SchemaType.STRING)),
        @Content(
            mediaType = MediaType.APPLICATION_JSON,
            schema = @Schema(implementation = AnchorsDto.class))
      })
  @APIResponse(responseCode = "304", description = "If-None-Match names the current version")
  @APIResponse(
      responseCode = "503",
      description = "No anchor is loaded (the volume is unreadable)",
      content =
          @Content(
              mediaType = MediaType.APPLICATION_JSON,
              schema = @Schema(implementation = ErrorBody.class)))
  public Response getAnchors(@Context HttpHeaders headers, @Context Request request) {
    Anchors.Bundle bundle = anchors.bundle();
    MediaType type = representation(headers);
    boolean json = MediaType.APPLICATION_JSON_TYPE.isCompatible(type);
    if (bundle.anchors().isEmpty()) {
      LOG.warn("the anchors were asked for, and none is loaded");
      return Response.status(Response.Status.SERVICE_UNAVAILABLE)
          .type(json ? MediaType.APPLICATION_JSON_TYPE : MediaType.TEXT_PLAIN_TYPE)
          .entity(json ? new ErrorBody("no anchor is loaded") : "no anchor is loaded\n")
          .build();
    }
    EntityTag tag = new EntityTag(bundle.version());
    Response.ResponseBuilder unchanged = request.evaluatePreconditions(tag);
    if (unchanged != null) {
      return unchanged.tag(tag).header(HttpHeaders.VARY, HttpHeaders.ACCEPT).build();
    }
    return Response.ok(json ? AnchorsDto.of(bundle) : bundle.pem(), type)
        .tag(tag)
        .header(HttpHeaders.VARY, HttpHeaders.ACCEPT)
        .build();
  }

  @POST
  @Path("/rotate")
  @RolesAllowed(Roles.ADMIN)
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      operationId = "rotateAnchors",
      summary = "Start a rotation: a new PENDING anchor, ACTIVE after the overlap")
  @APIResponse(
      responseCode = "201",
      description = "The new PENDING anchor",
      content =
          @Content(
              mediaType = MediaType.APPLICATION_JSON,
              schema = @Schema(implementation = AnchorDto.class)))
  @APIResponse(
      responseCode = "409",
      description = "An anchor is already PENDING; anchorId names it",
      content =
          @Content(
              mediaType = MediaType.APPLICATION_JSON,
              schema = @Schema(implementation = ErrorBody.class)))
  public Response rotateAnchors() {
    Anchor made = anchors.rotate();
    return Response.status(Response.Status.CREATED).entity(AnchorDto.of(made)).build();
  }

  /**
   * The form to answer in, by the caller's {@code Accept} in its own order of preference: JSON when
   * {@code application/json} comes first, {@code application/x-pem-file} when that does, and {@code
   * text/plain} for {@code text/*}, a wildcard or no {@code Accept} at all.
   */
  static MediaType representation(HttpHeaders headers) {
    for (MediaType accepted : headers.getAcceptableMediaTypes()) {
      if (accepted.isWildcardType()) {
        return MediaType.TEXT_PLAIN_TYPE;
      }
      if ("application".equalsIgnoreCase(accepted.getType())) {
        if ("json".equalsIgnoreCase(accepted.getSubtype())) {
          return MediaType.APPLICATION_JSON_TYPE;
        }
        if ("x-pem-file".equalsIgnoreCase(accepted.getSubtype()) || accepted.isWildcardSubtype()) {
          return MediaType.valueOf(PEM);
        }
      }
      if ("text".equalsIgnoreCase(accepted.getType())
          && (accepted.isWildcardSubtype() || "plain".equalsIgnoreCase(accepted.getSubtype()))) {
        return MediaType.TEXT_PLAIN_TYPE;
      }
    }
    return MediaType.TEXT_PLAIN_TYPE;
  }
}
