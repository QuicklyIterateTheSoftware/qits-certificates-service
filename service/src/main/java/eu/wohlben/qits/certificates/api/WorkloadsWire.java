package eu.wohlben.qits.certificates.api;

import eu.wohlben.qits.certificates.control.WorkloadCertificates;
import java.time.Instant;

/** The workload certificate door's JSON (qits-2756). Every nested type is listed in {@link ApiWireReflection}. */
public final class WorkloadsWire {

  private WorkloadsWire() {}

  /** {@code POST /workload-certificates}'s body: one PKCS#10 PEM. Only its key is used. */
  public record WorkloadCertificateRequest(String csr) {}

  /**
   * An issued workload certificate.
   *
   * @param certificate the certificate, one {@code CERTIFICATE} PEM block
   * @param chain the certificate, then the ACTIVE anchor that signed it
   * @param serial its serial, lower-case hex
   * @param anchorId the ACTIVE anchor that signed it
   * @param principal who it names, {@code <kind>:<name>}: decided from the caller's bearer alone
   */
  public record WorkloadCertificateDto(
      String certificate,
      String chain,
      String serial,
      Instant notAfter,
      String anchorId,
      String principal) {

    static WorkloadCertificateDto of(WorkloadCertificates.Workload workload) {
      return new WorkloadCertificateDto(
          workload.certificatePem(),
          workload.chainPem(),
          workload.serial(),
          workload.notAfter(),
          workload.anchorId(),
          workload.principal());
    }
  }
}
