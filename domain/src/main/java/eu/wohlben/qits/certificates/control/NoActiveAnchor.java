package eu.wohlben.qits.certificates.control;

/** No anchor can sign a leaf now: none is ACTIVE, or the ACTIVE one has expired. The door's 503. */
public class NoActiveAnchor extends RuntimeException {

  public NoActiveAnchor(String message) {
    super(message, null, false, false);
  }
}
