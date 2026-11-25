package eu.wohlben.qits.certificates.api;

import eu.wohlben.qits.certificates.control.Leaves;
import java.time.Instant;

/** The leaf door's JSON. Every nested type is listed in {@link ApiWireReflection}. */
public final class LeavesWire {

  private LeavesWire() {}

  /** {@code POST /leaves}'s body: one PKCS#10 PEM. */
  public record LeafRequest(String csr) {}

  /**
   * An issued leaf.
   *
   * @param certificate the leaf, one {@code CERTIFICATE} PEM block
   * @param chain the leaf, then the ACTIVE anchor that signed it
   * @param serial the leaf's serial, lower-case hex
   * @param anchorId the ACTIVE anchor that signed it
   */
  public record LeafDto(
      String certificate, String chain, String serial, Instant notAfter, String anchorId) {

    static LeafDto of(Leaves.Leaf leaf) {
      return new LeafDto(
          leaf.certificatePem(), leaf.chainPem(), leaf.serial(), leaf.notAfter(), leaf.anchorId());
    }
  }

  /** A name the leaf may not carry: {@code {"error":"name refused","name":…}}. */
  public record NameRefused(String error, String name) {

    NameRefused(String name) {
      this("name refused", name);
    }
  }
}
