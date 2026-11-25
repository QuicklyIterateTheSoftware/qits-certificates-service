package eu.wohlben.qits.certificates.control;

/**
 * The volume refused a write or a read the CA needed. Its message names the anchor and the file,
 * never their content.
 */
public class AnchorStoreException extends RuntimeException {

  public AnchorStoreException(String message, Throwable cause) {
    super(message, cause);
  }

  public AnchorStoreException(String message) {
    super(message);
  }
}
