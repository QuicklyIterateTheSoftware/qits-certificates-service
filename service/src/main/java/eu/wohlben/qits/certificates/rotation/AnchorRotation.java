package eu.wohlben.qits.certificates.rotation;

import eu.wohlben.qits.certificates.control.AnchorStoreException;
import eu.wohlben.qits.certificates.control.Anchors;
import io.quarkus.runtime.StartupEvent;
import io.quarkus.scheduler.Scheduled;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

/**
 * Runs the anchors' state machine ({@link Anchors#tick()}): once at startup, after loading the
 * volume (which is also where the first boot makes the first ACTIVE anchor), and then every 24
 * hours. A volume fault is an ERROR in the log and leaves readiness to say the rest.
 */
@ApplicationScoped
public class AnchorRotation {

  private static final Logger LOG = Logger.getLogger(AnchorRotation.class);

  @Inject Anchors anchors;

  void onStart(@Observes StartupEvent start) {
    anchors.start();
  }

  @Scheduled(
      identity = "anchor-rotation",
      every = "24h",
      concurrentExecution = Scheduled.ConcurrentExecution.SKIP)
  void daily() {
    try {
      anchors.tick();
    } catch (AnchorStoreException e) {
      LOG.errorf("the daily anchor rotation failed: %s", e.getMessage());
    }
  }
}
