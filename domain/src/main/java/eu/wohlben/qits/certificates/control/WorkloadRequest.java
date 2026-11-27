package eu.wohlben.qits.certificates.control;

import java.util.List;
import java.util.Objects;

/**
 * Who a workload certificate is for, as the service decided it from the caller's bearer alone
 * (qits-auth-core's {@code WorkloadPrincipal}, epic qits-2626). The domain takes the decision as
 * data and never reads a token, so it carries no web stack.
 *
 * @param requester the caller's {@code sub}, for the audit line
 * @param principal {@code <kind>:<name>}, the certificate's CN (informational) and the answer's
 *     {@code principal}
 * @param uris the URI subjectAltNames: {@code urn:qits:principal:<kind>:<name>}, and an agent's
 *     {@code urn:qits:project:<id>}
 * @param dnsNames the dNSName subjectAltNames: an application's own wire alias {@code
 *     <env>-<application>}, else none
 */
public record WorkloadRequest(
    String requester, String principal, List<String> uris, List<String> dnsNames) {

  public WorkloadRequest {
    Objects.requireNonNull(principal, "principal");
    uris = List.copyOf(uris);
    dnsNames = List.copyOf(dnsNames);
    if (uris.isEmpty()) {
      throw new IllegalArgumentException("a workload certificate names its principal in a URI");
    }
  }

  /** A certificate with a DNS name serves TLS too: EKU serverAuth beside clientAuth. */
  public boolean serverAuth() {
    return !dnsNames.isEmpty();
  }
}
