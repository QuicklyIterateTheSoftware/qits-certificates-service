package eu.wohlben.qits.certificates.rotation;

import eu.wohlben.qits.certificates.control.Entropy;
import io.quarkus.arc.DefaultBean;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import java.security.SecureRandom;

/**
 * A leaf's randomness: a fresh {@link SecureRandom} per leaf. A {@code @DefaultBean}, so a suite
 * that declares an {@link Entropy} bean of its own makes a recorded leaf the same bytes every run.
 *
 * <p>The bean is a method reference and holds no {@link SecureRandom}: the native image refuses one
 * seeded at build time in its heap.
 */
@Singleton
public class Entropies {

  @Produces
  @Singleton
  @DefaultBean
  Entropy entropy() {
    return SecureRandom::new;
  }
}
