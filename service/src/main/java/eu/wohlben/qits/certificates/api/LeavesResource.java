package eu.wohlben.qits.certificates.api;

import eu.wohlben.qits.auth.MachineIdentity;
import eu.wohlben.qits.certificates.api.AnchorsWire.ErrorBody;
import eu.wohlben.qits.certificates.api.LeavesWire.LeafDto;
import eu.wohlben.qits.certificates.api.LeavesWire.LeafRequest;
import eu.wohlben.qits.certificates.api.LeavesWire.NameRefused;
import eu.wohlben.qits.certificates.control.LeafRefused;
import eu.wohlben.qits.certificates.control.Leaves;
import eu.wohlben.qits.certificates.control.NoActiveAnchor;
import io.quarkus.security.ForbiddenException;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Optional;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.RequestBody;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.jboss.resteasy.reactive.server.ServerExceptionMapper;

/**
 * The leaf door, {@code POST /leaves}: {@code qits:system}, and then the caller's JWT {@code sub}
 * must be in {@code qits.certificates.leaf.requesters} ({@link Leaves}, {@code control/LeafPolicy}).
 *
 * <p>Every answer of this door is audited on {@value Leaves#AUDIT_LOGGER}, a caller without {@code
 * qits:system} included: its 403 is mapped here, on this resource only, so it leaves the same
 * {@code REFUSED} line a non-requester does.
 */
@Path("/leaves")
public class LeavesResource {

  static final String NOT_A_REQUESTER = "not a leaf requester";

  @Inject Leaves leaves;

  @Inject SecurityIdentity identity;

  @POST
  @RolesAllowed(Roles.SYSTEM)
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      operationId = "issueLeaf",
      summary = "Sign a leaf certificate for a CSR, with the ACTIVE anchor")
  @RequestBody(
      required = true,
      content =
          @Content(
              mediaType = MediaType.APPLICATION_JSON,
              schema = @Schema(implementation = LeafRequest.class)))
  @APIResponse(
      responseCode = "201",
      description = "The leaf, and the chain: the leaf then the ACTIVE anchor",
      content =
          @Content(
              mediaType = MediaType.APPLICATION_JSON,
              schema = @Schema(implementation = LeafDto.class)))
  @APIResponse(
      responseCode = "400",
      description =
          "The CSR breaks a rule ({\"error\":<reason>}), or a name does ({\"error\":\"name"
              + " refused\",\"name\":…})",
      content =
          @Content(
              mediaType = MediaType.APPLICATION_JSON,
              schema = @Schema(oneOf = {ErrorBody.class, NameRefused.class})))
  @APIResponse(
      responseCode = "403",
      description = "The caller is not a leaf requester",
      content =
          @Content(
              mediaType = MediaType.APPLICATION_JSON,
              schema = @Schema(implementation = ErrorBody.class)))
  @APIResponse(
      responseCode = "503",
      description = "No anchor is ACTIVE",
      content =
          @Content(
              mediaType = MediaType.APPLICATION_JSON,
              schema = @Schema(implementation = ErrorBody.class)))
  public Response issueLeaf(LeafRequest request) {
    Leaves.Leaf leaf = leaves.issue(requester(), request == null ? null : request.csr());
    return Response.status(Response.Status.CREATED).entity(LeafDto.of(leaf)).build();
  }

  /** A caller without {@code qits:system}: the same 403 a non-requester gets, and audited. */
  @ServerExceptionMapper
  public Response forbidden(ForbiddenException denied) {
    leaves.refusedAtTheDoor(requester(), "not " + Roles.SYSTEM);
    return Response.status(Response.Status.FORBIDDEN)
        .type(MediaType.APPLICATION_JSON)
        .entity(new ErrorBody(NOT_A_REQUESTER))
        .build();
  }

  @ServerExceptionMapper
  public Response refused(LeafRefused refused) {
    Response.ResponseBuilder answer =
        switch (refused.kind()) {
          case NOT_REQUESTER ->
              Response.status(Response.Status.FORBIDDEN).entity(new ErrorBody(NOT_A_REQUESTER));
          case NAME ->
              Response.status(Response.Status.BAD_REQUEST).entity(new NameRefused(refused.name()));
          case CSR ->
              Response.status(Response.Status.BAD_REQUEST).entity(new ErrorBody(refused.reason()));
        };
    return answer.type(MediaType.APPLICATION_JSON).build();
  }

  @ServerExceptionMapper
  public Response unavailable(NoActiveAnchor none) {
    return Response.status(Response.Status.SERVICE_UNAVAILABLE)
        .type(MediaType.APPLICATION_JSON)
        .entity(new ErrorBody(none.getMessage()))
        .build();
  }

  /** The validated token's {@code sub}; the principal's name for an identity without a JWT. */
  private String requester() {
    if (identity == null || identity.isAnonymous()) {
      return null;
    }
    return MachineIdentity.claim(identity, "sub")
        .or(
            () ->
                Optional.ofNullable(
                    identity.getPrincipal() == null ? null : identity.getPrincipal().getName()))
        .orElse(null);
  }
}
