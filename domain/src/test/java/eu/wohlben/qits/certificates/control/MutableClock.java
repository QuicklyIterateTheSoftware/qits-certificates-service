package eu.wohlben.qits.certificates.control;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/** A clock a test sets and moves. */
final class MutableClock extends Clock {

  private volatile Instant now;

  MutableClock(Instant now) {
    this.now = now;
  }

  void set(Instant at) {
    now = at;
  }

  void advance(Duration by) {
    now = now.plus(by);
  }

  @Override
  public Instant instant() {
    return now;
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
