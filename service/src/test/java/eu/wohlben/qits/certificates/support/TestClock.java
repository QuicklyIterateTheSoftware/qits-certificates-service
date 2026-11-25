package eu.wohlben.qits.certificates.support;

import jakarta.inject.Singleton;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/**
 * The suite's clock: the system clock until a test pins it, then whatever the test sets. Being a
 * {@link Clock} bean, it replaces the {@code @DefaultBean} the service produces, so every rotation
 * decision in a {@code @QuarkusTest} runs on it.
 */
@Singleton
public class TestClock extends Clock {

  private volatile Instant pinned;

  /** Pins the clock at {@code at}. */
  public void set(Instant at) {
    pinned = at;
  }

  /** Moves a pinned clock on by {@code by}. */
  public void advance(Duration by) {
    pinned = instant().plus(by);
  }

  /** Back to the system clock. */
  public void reset() {
    pinned = null;
  }

  @Override
  public Instant instant() {
    Instant at = pinned;
    return at == null ? Instant.now() : at;
  }

  @Override
  public ZoneId getZone() {
    return ZoneOffset.UTC;
  }

  @Override
  public Clock withZone(ZoneId zone) {
    return this;
  }
}
