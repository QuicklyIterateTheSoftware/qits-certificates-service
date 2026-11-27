package eu.wohlben.qits.certificates.api;

import eu.wohlben.qits.auth.MachineIdentity;
import eu.wohlben.qits.auth.WorkloadPrincipal;
import eu.wohlben.qits.certificates.api.AnchorsWire.ErrorBody;
import eu.wohlben.qits.certificates.api.WorkloadsWire.WorkloadCertificateDto;
import eu.wohlben.qits.certificates.api.WorkloadsWire.WorkloadCertificateRequest;
import eu.wohlben.qits.certificates.control.LeafRefused;
import eu.wohlben.qits.certificates.control.NoActiveAnchor;
import eu.wohlben.qits.certificates.control.WorkloadCertificates;
import eu.wohlben.qits.certificates.control.WorkloadRefused;
import eu.wohlben.qits.certificates.control.WorkloadRequest;
import io.quarkus.security.Authenticated;
import io.quarkus.security.UnauthorizedException;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.RequestBody;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.jboss.resteasy.reactive.server.ServerExceptionMapper;

/**
 * The workload certificate door, {@code POST /workload-certificates} (epic qits-2626, qits-2756):
 * any platform bearer gets a short-lived client certificate for <b>its own</b> principal.
 *
 * <ul>
 *   <li><b>Who it is for</b> comes from the validated token alone, through qits-auth-core's {@link
 *       WorkloadPrincipal}, the same grammar qits-egress keys its grants with. The CSR gives only its
 *       key: its subject and the names it asks for are never read.
 *   <li><b>Refused with 403</b>: a token {@link WorkloadPrincipal#issuanceRefusal} refuses (an
 *       exchanged token, a person's, a {@code subject:} principal, a name unfit for a certificate),
 *       and an identity that is not a JWT.
 *   <li><b>An application</b> ({@code application:<app>}) also gets its own wire alias {@code
 *       <QITS_ENVIRONMENT>-<app>} as a DNS name, with EKU serverAuth, so it can serve TLS on the wire
 *       alias with the same certificate.
 *   <li>Opaque {@code qits_tok_} callers arrive as the JWT the edge introspected them into, so they
 *       map like any other token.
 * </ul>
 *
 * <p>Every answer of this door is one audit line ({@link WorkloadCertificates}), the 401 of a caller
 * without a bearer included.
 */
@Path("/workload-certificates")
public class WorkloadCertificatesResource {

  /** A DNS label: what an application's wire alias must be to go into the certificate. */
  private static final Pattern DNS_LABEL = Pattern.compile("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?");

  static final String NO_BEARER = "a bearer token is required";

  @Inject WorkloadCertificates workloads;

  @Inject SecurityIdentity identity;

  @ConfigProperty(name = "qits.certificates.environment")
  String environment;

  @POST
  @Authenticated
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(
      operationId = "issueWorkloadCertificate",
      summary = "Sign a client certificate for the caller's own principal, for a CSR's key")
  @RequestBody(
      required = true,
      content =
          @Content(
              mediaType = MediaType.APPLICATION_JSON,
              schema = @Schema(implementation = WorkloadCertificateRequest.class)))
  @APIResponse(
      responseCode = "201",
      description = "The certificate, and the chain: the certificate then the ACTIVE anchor",
      content =
          @Content(
              mediaType = MediaType.APPLICATION_JSON,
              schema = @Schema(implementation = WorkloadCertificateDto.class)))
  @APIResponse(
      responseCode = "400",
      description = "The CSR does not parse, does not verify, or has a key this CA does not take",
      content =
          @Content(
              mediaType = MediaType.APPLICATION_JSON,
              schema = @Schema(implementation = ErrorBody.class)))
  @APIResponse(
      responseCode = "401",
      description = "No bearer",
      content =
          @Content(
              mediaType = MediaType.APPLICATION_JSON,
              schema = @Schema(implementation = ErrorBody.class)))
  @APIResponse(
      responseCode = "403",
      description = "The caller's token may not have a workload certificate; error names why",
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
  public Response issueWorkloadCertificate(WorkloadCertificateRequest request) {
    WorkloadRequest workload = workload();
    WorkloadCertificates.Workload issued =
        workloads.issue(workload, request == null ? null : request.csr());
    return Response.status(Response.Status.CREATED)
        .entity(WorkloadCertificateDto.of(issued))
        .build();
  }

  /** Who the certificate is for, from the token; a refusal is audited and thrown. */
  private WorkloadRequest workload() {
    String requester = requester();
    if (!(identity.getPrincipal() instanceof JsonWebToken token)) {
      throw refuse(requester, null, "no workload principal");
    }
    WorkloadPrincipal principal = WorkloadPrincipal.fromToken(token, environment);
    String refusal = WorkloadPrincipal.issuanceRefusal(token, environment);
    if (refusal != null) {
      throw refuse(requester, principal.toString(), refusal);
    }
    List<String> dns = List.of();
    if (principal.application() != null) {
      String alias = environment + "-" + principal.application();
      if (alias.length() <= 63 && DNS_LABEL.matcher(alias).matches()) {
        dns = List.of(alias);
      }
    }
    return new WorkloadRequest(requester, principal.toString(), principal.uris(), dns);
  }

  /** Audits the refusal and returns it, for the caller to throw. */
  private WorkloadRefused refuse(String requester, String principal, String reason) {
    workloads.refused(requester, principal, reason);
    return new WorkloadRefused(reason);
  }

  /** A caller without a bearer: 401, and audited like every other answer of this door. */
  @ServerExceptionMapper
  public Response unauthorized(UnauthorizedException denied) {
    workloads.refused(null, null, "no bearer");
    return Response.status(Response.Status.UNAUTHORIZED)
        .header("WWW-Authenticate", "Bearer")
        .type(MediaType.APPLICATION_JSON)
        .entity(new ErrorBody(NO_BEARER))
        .build();
  }

  @ServerExceptionMapper
  public Response refused(WorkloadRefused refused) {
    return Response.status(Response.Status.FORBIDDEN)
        .type(MediaType.APPLICATION_JSON)
        .entity(new ErrorBody(refused.reason()))
        .build();
  }

  @ServerExceptionMapper
  public Response badCsr(LeafRefused refused) {
    return Response.status(Response.Status.BAD_REQUEST)
        .type(MediaType.APPLICATION_JSON)
        .entity(new ErrorBody(refused.reason()))
        .build();
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
