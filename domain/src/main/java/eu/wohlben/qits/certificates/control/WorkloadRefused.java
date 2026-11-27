package eu.wohlben.qits.certificates.control;

/**
 * The caller's token may not have a workload certificate: a person's, an exchanged one, one of no
 * workload principal, or a name that could read two ways. The door answers 403; {@link #reason()}
 * is the audit line's reason and the error body.
 */
public class WorkloadRefused extends RuntimeException {

  private final String reason;

  public WorkloadRefused(String reason) {
    super(reason, null, false, false);
    this.reason = reason;
  }

  public String reason() {
    return reason;
  }
}
