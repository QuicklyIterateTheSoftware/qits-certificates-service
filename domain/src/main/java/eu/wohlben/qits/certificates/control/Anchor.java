package eu.wohlben.qits.certificates.control;

import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Instant;
import javax.security.auth.x500.X500Principal;

/**
 * One loaded anchor: its state, its certificate and the certificate's PEM, and the directory it
 * lives in. It never holds the private key: {@link Anchors#activeKey()} reads that from {@code
 * key.pem} when it is needed.
 */
public record Anchor(AnchorState state, X509Certificate certificate, String certificatePem, Path directory) {

  public String id() {
    return state.id();
  }

  public AnchorStatus status() {
    return state.status();
  }

  /** {@code CN=qits platform CA <env> <yyyy-MM>, O=qits}. */
  public String subject() {
    return certificate.getSubjectX500Principal().getName(X500Principal.RFC1779);
  }

  /** The serial number, lower-case hex. */
  public String serial() {
    return certificate.getSerialNumber().toString(16);
  }

  public Instant notBefore() {
    return certificate.getNotBefore().toInstant();
  }

  public Instant notAfter() {
    return certificate.getNotAfter().toInstant();
  }

  public Anchor with(AnchorState next) {
    return new Anchor(next, certificate, certificatePem, directory);
  }
}
