package eu.wohlben.qits.certificates.api;

import eu.wohlben.qits.certificates.api.AnchorsWire.ErrorBody;
import eu.wohlben.qits.certificates.control.AnchorStoreException;
import eu.wohlben.qits.certificates.control.PendingAnchorExists;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.server.ServerExceptionMapper;

/**
 * The domain's refusals: 409 for a second PENDING anchor, 500 for a volume fault. Each body is an
 * {@link ErrorBody} whose text names anchors and files, never their content.
 */
public class AnchorsExceptionMapper {

  private static final Logger LOG = Logger.getLogger(AnchorsExceptionMapper.class);

  @ServerExceptionMapper
  public Response pending(PendingAnchorExists conflict) {
    return Response.status(Response.Status.CONFLICT)
        .type(MediaType.APPLICATION_JSON)
        .entity(new ErrorBody("an anchor is already PENDING", conflict.anchorId()))
        .build();
  }

  @ServerExceptionMapper
  public Response store(AnchorStoreException fault) {
    LOG.errorf("the anchor store failed: %s", fault.getMessage());
    return Response.serverError()
        .type(MediaType.APPLICATION_JSON)
        .entity(new ErrorBody("the anchor store failed"))
        .build();
  }
}
