package eu.wohlben.qits.certificates.health;

import eu.wohlben.qits.certificates.control.CertificateSmoke;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.HealthCheckResponseBuilder;
import org.eclipse.microprofile.health.Readiness;
import org.jboss.logging.Logger;

/**
 * {@code certificates-crypto}: UP once {@link CertificateSmoke} has signed a CSR end to end in this
 * process. It runs once, at startup, so a broken crypto path is an ERROR in the boot log and a
 * readiness that never comes up — the deploy's health gate refuses the container rather than
 * letting it answer its first leaf request with a 500. That gate is what proves the native image's
 * Bouncy Castle in production; {@code CertificatesBootstrapIT} proves it against the packaged
 * artifact (the binary, under {@code -Dnative}).
 *
 * <p>The data names subjects only. No answer of this service ever carries key material.
 */
@Readiness
@ApplicationScoped
public class CryptoReadiness implements HealthCheck {

  static final String NAME = "certificates-crypto";

  private static final Logger LOG = Logger.getLogger(CryptoReadiness.class);

  private volatile HealthCheckResponse outcome;

  void onStart(@Observes StartupEvent start) {
    outcome = prove();
  }

  @Override
  public HealthCheckResponse call() {
    HealthCheckResponse known = outcome;
    if (known == null) {
      known = prove();
      outcome = known;
    }
    return known;
  }

  private static HealthCheckResponse prove() {
    HealthCheckResponseBuilder response = HealthCheckResponse.named(NAME);
    try {
      CertificateSmoke.Result result = CertificateSmoke.run();
      LOG.infof(
          "certificates crypto ready: anchor %s signed leaf %s",
          result.anchorSubject(), result.leafSubject());
      return response
          .up()
          .withData("anchorSubject", result.anchorSubject())
          .withData("leafSubject", result.leafSubject())
          .build();
    } catch (Exception | LinkageError e) {
      LOG.error("certificates crypto is broken: no anchor can be made and no leaf signed", e);
      return response.down().withData("error", e.getClass().getName()).build();
    }
  }
}
