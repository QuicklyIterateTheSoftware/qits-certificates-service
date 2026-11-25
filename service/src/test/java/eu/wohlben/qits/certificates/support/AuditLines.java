package eu.wohlben.qits.certificates.support;

import eu.wohlben.qits.certificates.control.Leaves;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.jboss.logmanager.ExtLogRecord;

/** The audit lines the service writes while it listens, formatted, with their level. */
public final class AuditLines extends Handler implements AutoCloseable {

  /** One audit record: its level and its formatted message. */
  public record Line(Level level, String message) {}

  private final List<Line> lines = Collections.synchronizedList(new ArrayList<>());

  private final Logger logger = Logger.getLogger(Leaves.AUDIT_LOGGER);

  public static AuditLines listen() {
    AuditLines audit = new AuditLines();
    audit.setLevel(Level.ALL);
    audit.logger.addHandler(audit);
    return audit;
  }

  public List<Line> lines() {
    return List.copyOf(lines);
  }

  /** The one line written since the last {@link #clear()}; fails unless there is exactly one. */
  public String only() {
    List<Line> now = lines();
    if (now.size() != 1) {
      throw new AssertionError("expected one audit line, got " + now);
    }
    if (now.get(0).level().intValue() != Level.INFO.intValue()) {
      throw new AssertionError("the audit line is not INFO: " + now.get(0));
    }
    return now.get(0).message();
  }

  public void clear() {
    lines.clear();
  }

  @Override
  public void publish(LogRecord record) {
    if (!Leaves.AUDIT_LOGGER.equals(record.getLoggerName())) {
      return;
    }
    lines.add(
        new Line(
            record.getLevel(),
            record instanceof ExtLogRecord ext ? ext.getFormattedMessage() : record.getMessage()));
  }

  @Override
  public void flush() {}

  @Override
  public void close() {
    logger.removeHandler(this);
  }
}
