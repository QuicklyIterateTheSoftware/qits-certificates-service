package eu.wohlben.qits.certificates.support;

import eu.wohlben.qits.certificates.control.Entropy;
import jakarta.inject.Singleton;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * The suite's leaf randomness: a fresh {@link SecureRandom} per leaf, as the service's, until a test
 * pins it. Pinned, every leaf gets a {@code SHA1PRNG} seeded with the same bytes, so its serial and
 * its signature's nonce, and with the clock and the fixture anchor pinned too, the whole leaf, are
 * the same bytes on every run. Being an {@link Entropy} bean, it replaces the service's
 * {@code @DefaultBean}.
 */
@Singleton
public class TestEntropy implements Entropy {

  static final long SEED = 2524L;

  private volatile boolean pinned;

  public void pin() {
    pinned = true;
  }

  public void reset() {
    pinned = false;
  }

  @Override
  public SecureRandom secureRandom() {
    if (!pinned) {
      return new SecureRandom();
    }
    try {
      SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
      random.setSeed(SEED);
      return random;
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("no SHA1PRNG", e);
    }
  }
}
