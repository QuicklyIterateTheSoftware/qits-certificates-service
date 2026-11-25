package eu.wohlben.qits.certificates.rotation;

import io.quarkus.arc.DefaultBean;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import java.time.Clock;

/**
 * The CA's time: the system clock in UTC. A {@code @DefaultBean}, so a test that declares a {@link
 * Clock} bean of its own drives every rotation decision with it.
 */
@Singleton
public class Clocks {

  @Produces
  @Singleton
  @DefaultBean
  Clock clock() {
    return Clock.systemUTC();
  }
}
