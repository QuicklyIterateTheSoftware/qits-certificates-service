package eu.wohlben.qits.certificates.rotation;

import eu.wohlben.qits.certificates.control.WorkloadCertificates;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

/**
 * Builds {@link WorkloadCertificates} at startup, so that a {@code qits.certificates.workload.validity}
 * longer than the leaf validity fails the boot (and the deploy's health gate) rather than the first
 * request (qits-2756).
 */
@ApplicationScoped
public class WorkloadValidity {

  private static final Logger LOG = Logger.getLogger(WorkloadValidity.class);

  @Inject WorkloadCertificates workloads;

  void onStart(@Observes StartupEvent start) {
    LOG.infof("Workload certificates live %s", workloads.validity());
  }
}
