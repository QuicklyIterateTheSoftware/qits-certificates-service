package eu.wohlben.qits.certificates.control;

/** A rotation was asked for while an anchor is already PENDING: there is never more than one. */
public class PendingAnchorExists extends RuntimeException {

  private final String anchorId;

  public PendingAnchorExists(String anchorId) {
    super("anchor " + anchorId + " is already PENDING");
    this.anchorId = anchorId;
  }

  public String anchorId() {
    return anchorId;
  }
}
