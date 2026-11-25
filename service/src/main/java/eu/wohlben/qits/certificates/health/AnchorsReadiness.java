package eu.wohlben.qits.certificates.health;

import eu.wohlben.qits.certificates.control.Anchors;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.HealthCheckResponseBuilder;
import org.eclipse.microprofile.health.Readiness;

/**
 * {@code certificates-anchors}: UP once exactly one ACTIVE anchor is loaded and its {@code key.pem}
 * reads back as its certificate's key — checked on every call, so a key lost from the volume takes
 * the container out of rotation. Until the first boot has made its anchor it is DOWN, and the
 * deploy's health gate on {@code /certificates/q/health/ready} waits.
 *
 * <p>Making that anchor is also this service's proof of Bouncy Castle in the packaged artifact: the
 * certificate is built, written as PEM and parsed back by bcpkix in the running process, the native
 * binary in production.
 *
 * <p>The data names the anchor's id and subject, or why it is down. Never key material.
 */
@Readiness
@ApplicationScoped
public class AnchorsReadiness implements HealthCheck {

  static final String NAME = "certificates-anchors";

  @Inject Anchors anchors;

  @Override
  public HealthCheckResponse call() {
    Anchors.Readiness readiness = anchors.readiness();
    HealthCheckResponseBuilder response = HealthCheckResponse.named(NAME);
    if (!readiness.up()) {
      return response.down().withData("reason", readiness.reason()).build();
    }
    return response
        .up()
        .withData("activeAnchor", readiness.active().id())
        .withData("subject", readiness.active().subject())
        .withData("published", anchors.bundle().anchors().size())
        .build();
  }
}
