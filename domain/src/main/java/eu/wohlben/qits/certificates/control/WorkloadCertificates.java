package eu.wohlben.qits.certificates.control;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * <b>Signs workload client certificates</b> (epic qits-2626, qits-2756) with the ACTIVE anchor. Who
 * a certificate is for is decided before this class is asked, from the caller's bearer alone
 * ({@link WorkloadRequest}). From the CSR only the key is taken ({@link LeafPolicy#key}): its
 * subject and the names it asks for never reach the certificate.
 *
 * <p><b>Validity</b> is {@code qits.certificates.workload.validity} (P1D), capped by the ACTIVE
 * anchor's {@code notAfter}. It may not exceed {@code qits.certificates.leaf.validity}: a RETIRING
 * anchor stays published for the leaf validity plus a day, so everything it signed expires while it
 * is still trusted. A longer value fails the service at startup. There is no revocation: a
 * principal is cut off by deleting its token, after which it cannot renew.
 *
 * <p><b>Every decision is one INFO line</b> on {@value Leaves#AUDIT_LOGGER}, beside the leaves':
 *
 * <pre>
 * certificates decision=ISSUED|REFUSED kind=workload requester=&lt;sub&gt; principal=&lt;p&gt; names=&lt;uris,dns&gt; serial=&lt;hex&gt; anchor=&lt;id&gt; notAfter=&lt;iso&gt; reason=&lt;…&gt;
 * </pre>
 *
 * A value that does not apply is {@code -}; the reason is last. The line never carries the CSR, a
 * key or a bearer.
 */
@Singleton
public class WorkloadCertificates {

  private static final Logger AUDIT = Logger.getLogger(Leaves.AUDIT_LOGGER);

  /**
   * An issued workload certificate.
   *
   * @param certificatePem the certificate, one {@code CERTIFICATE} PEM block
   * @param chainPem the certificate, then the ACTIVE anchor that signed it
   * @param serial its serial, lower-case hex
   */
  public record Workload(
      String certificatePem,
      String chainPem,
      String serial,
      Instant notAfter,
      String anchorId,
      String principal,
      X509Certificate certificate) {}

  private final Anchors anchors;

  private final Duration validity;

  private final Clock clock;

  private final Entropy entropy;

  @Inject
  public WorkloadCertificates(
      Anchors anchors,
      @ConfigProperty(name = "qits.certificates.workload.validity", defaultValue = "P1D")
          Duration validity,
      @ConfigProperty(name = "qits.certificates.leaf.validity", defaultValue = "P7D")
          Duration leafValidity,
      Clock clock,
      Entropy entropy) {
    if (validity.isNegative() || validity.isZero()) {
      throw new IllegalStateException(
          "qits.certificates.workload.validity must be positive, not " + validity);
    }
    if (validity.compareTo(leafValidity) > 0) {
      throw new IllegalStateException(
          "qits.certificates.workload.validity ("
              + validity
              + ") exceeds qits.certificates.leaf.validity ("
              + leafValidity
              + "): a RETIRING anchor would leave the bundle while certificates it signed live");
    }
    this.anchors = anchors;
    this.validity = validity;
    this.clock = clock;
    this.entropy = entropy;
  }

  public Duration validity() {
    return validity;
  }

  /**
   * Signs a workload certificate for {@code request} over the key of {@code csr}.
   *
   * @throws LeafRefused {@link LeafRefused.Kind#CSR}: the CSR does not parse, verify or have a key
   *     this CA takes
   * @throws NoActiveAnchor no anchor is ACTIVE, or the ACTIVE one has expired
   * @throws AnchorStoreException the ACTIVE anchor's key cannot be read, or signing failed
   */
  public Workload issue(WorkloadRequest request, String csr) {
    List<String> names = names(request);
    LeafPolicy.CsrKey key;
    try {
      key = LeafPolicy.key(csr);
    } catch (LeafRefused refused) {
      audit("REFUSED", request.requester(), request.principal(), names, null, null, null, refused.reason());
      throw refused;
    }
    Optional<Anchors.Signer> signer;
    try {
      signer = anchors.signer();
    } catch (AnchorStoreException e) {
      refused(request, names, "the ACTIVE anchor's key cannot be read");
      throw e;
    }
    if (signer.isEmpty()) {
      refused(request, names, "no anchor is ACTIVE");
      throw new NoActiveAnchor("no anchor is ACTIVE");
    }
    Instant now = clock.instant();
    Anchor anchor = signer.get().anchor();
    if (!anchor.notAfter().isAfter(now)) {
      refused(request, names, "the ACTIVE anchor has expired");
      throw new NoActiveAnchor("the ACTIVE anchor has expired");
    }
    Instant wanted = now.plus(validity);
    Instant notAfter = wanted.isAfter(anchor.notAfter()) ? anchor.notAfter() : wanted;
    X509Certificate certificate;
    String pem;
    try {
      certificate =
          WorkloadCrypto.sign(
              anchor,
              signer.get().key(),
              request,
              key.key(),
              key.rsa(),
              now.minus(Leaves.BACKDATE),
              notAfter,
              entropy.secureRandom());
      pem = AnchorCrypto.certificatePem(certificate);
    } catch (GeneralSecurityException | IOException e) {
      refused(request, names, "signing failed");
      throw new AnchorStoreException(
          "a workload certificate could not be signed by anchor "
              + anchor.id()
              + ": "
              + e.getClass().getSimpleName());
    }
    String serial = certificate.getSerialNumber().toString(16);
    Instant issuedNotAfter = certificate.getNotAfter().toInstant();
    audit(
        "ISSUED",
        request.requester(),
        request.principal(),
        names,
        serial,
        anchor.id(),
        issuedNotAfter,
        null);
    return new Workload(
        pem,
        pem + anchor.certificatePem(),
        serial,
        issuedNotAfter,
        anchor.id(),
        request.principal(),
        certificate);
  }

  /**
   * The audit line of a caller the service refused before asking here: no bearer, or a token that
   * may not have a workload certificate. {@code principal} may be null.
   */
  public void refused(String requester, String principal, String reason) {
    audit("REFUSED", requester, principal, List.of(), null, null, null, reason);
  }

  private void refused(WorkloadRequest request, List<String> names, String reason) {
    audit("REFUSED", request.requester(), request.principal(), names, null, null, null, reason);
  }

  private static List<String> names(WorkloadRequest request) {
    List<String> names = new ArrayList<>(request.uris());
    names.addAll(request.dnsNames());
    return names;
  }

  private static void audit(
      String decision,
      String requester,
      String principal,
      List<String> names,
      String serial,
      String anchor,
      Instant notAfter,
      String reason) {
    AUDIT.infof(
        "certificates decision=%s kind=workload requester=%s principal=%s names=%s serial=%s"
            + " anchor=%s notAfter=%s reason=%s",
        decision,
        orDash(LeafPolicy.printable(requester)),
        orDash(LeafPolicy.printable(principal)),
        names.isEmpty() ? "-" : LeafPolicy.printable(String.join(",", names)),
        orDash(serial),
        orDash(anchor),
        notAfter == null ? "-" : notAfter.toString(),
        orDash(reason));
  }

  private static String orDash(String value) {
    return value == null || value.isEmpty() ? "-" : value;
  }
}
