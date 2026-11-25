package eu.wohlben.qits.certificates.control;

import java.security.SecureRandom;

/**
 * Where a leaf's randomness comes from: its serial and its signature's nonce. The service produces
 * {@code SecureRandom::new}, a fresh instance per leaf; a suite replaces it to make a recorded leaf
 * the same bytes on every run.
 *
 * <p><b>Never a field holding a {@link SecureRandom}</b>: a native image refuses one seeded at build
 * time in its image heap. Ask for one per leaf.
 */
@FunctionalInterface
public interface Entropy {

  SecureRandom secureRandom();
}
