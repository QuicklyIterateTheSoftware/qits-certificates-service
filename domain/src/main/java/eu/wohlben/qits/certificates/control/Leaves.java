package eu.wohlben.qits.certificates.control;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * <b>Signs leaves</b> for the callers {@link LeafPolicy} admits, with the ACTIVE anchor.
 *
 * <p><b>Every decision is one INFO line</b> on {@value #AUDIT_LOGGER}:
 *
 * <pre>
 * certificates decision=ISSUED|REFUSED requester=&lt;sub&gt; names=&lt;a,b&gt; serial=&lt;hex&gt; anchor=&lt;id&gt; notAfter=&lt;iso&gt; reason=&lt;…&gt;
 * </pre>
 *
 * A value that does not apply is {@code -}; the reason is last, so it may hold spaces. The line never
 * carries the CSR or a key, and every caller-supplied value in it is made printable first.
 */
@Singleton
public class Leaves {

  public static final String AUDIT_LOGGER = "eu.wohlben.qits.certificates.audit";

  private static final Logger AUDIT = Logger.getLogger(AUDIT_LOGGER);

  private static final Logger LOG = Logger.getLogger(Leaves.class);

  /** How far a leaf's {@code notBefore} is set back, for callers whose clock lags. */
  static final Duration BACKDATE = AnchorCrypto.BACKDATE;

  /**
   * An issued leaf.
   *
   * @param certificatePem the leaf, one {@code CERTIFICATE} PEM block
   * @param chainPem the leaf, then the ACTIVE anchor that signed it
   * @param serial the leaf's serial, lower-case hex
   */
  public record Leaf(
      String certificatePem,
      String chainPem,
      String serial,
      Instant notAfter,
      String anchorId,
      List<String> names,
      X509Certificate certificate) {}

  private final Anchors anchors;

  private final LeafPolicy policy;

  private final Clock clock;

  private final Entropy entropy;

  @Inject
  public Leaves(
      Anchors anchors,
      @ConfigProperty(name = "qits.certificates.leaf.requesters", defaultValue = "dev-qits-egress")
          List<String> requesters,
      @ConfigProperty(name = "qits.certificates.domain") Optional<String> domain,
      @ConfigProperty(name = "qits.certificates.leaf.validity", defaultValue = "P7D")
          Duration validity,
      Clock clock,
      Entropy entropy) {
    this(anchors, new LeafPolicy(requesters, domain.orElse(null), validity), clock, entropy);
  }

  public Leaves(Anchors anchors, LeafPolicy policy, Clock clock, Entropy entropy) {
    this.anchors = anchors;
    this.policy = policy;
    this.clock = clock;
    this.entropy = entropy;
    if (policy.domain().isEmpty()) {
      LOG.warn(
          "qits.certificates.domain (QITS_DOMAIN) is blank: no name is refused as a platform host");
    }
  }

  public LeafPolicy policy() {
    return policy;
  }

  /**
   * Signs a leaf for {@code csr}, asked for by {@code requester} (the caller's {@code sub}).
   *
   * @throws LeafRefused the requester is not admitted, or the CSR or a name breaks a rule
   * @throws NoActiveAnchor no anchor is ACTIVE, or the ACTIVE one has expired
   * @throws AnchorStoreException the ACTIVE anchor's key cannot be read, or signing failed
   */
  public Leaf issue(String requester, String csr) {
    if (!policy.admits(requester)) {
      LeafRefused refused = LeafRefused.notRequester();
      refused(requester, List.of(), refused.reason());
      throw refused;
    }
    LeafPolicy.Request request;
    try {
      request = policy.check(csr);
    } catch (LeafRefused refused) {
      refused(requester, refused.names(), refused.reason());
      throw refused;
    }
    Optional<Anchors.Signer> signer;
    try {
      signer = anchors.signer();
    } catch (AnchorStoreException e) {
      refused(requester, request.names(), "the ACTIVE anchor's key cannot be read");
      throw e;
    }
    Instant now = clock.instant();
    if (signer.isEmpty()) {
      refused(requester, request.names(), "no anchor is ACTIVE");
      throw new NoActiveAnchor("no anchor is ACTIVE");
    }
    Anchor anchor = signer.get().anchor();
    if (!anchor.notAfter().isAfter(now)) {
      refused(requester, request.names(), "the ACTIVE anchor has expired");
      throw new NoActiveAnchor("the ACTIVE anchor has expired");
    }
    X509Certificate leaf;
    String pem;
    try {
      leaf =
          LeafCrypto.sign(
              anchor,
              signer.get().key(),
              request,
              now.minus(BACKDATE),
              policy.notAfter(now, anchor.notAfter()),
              entropy.secureRandom());
      pem = AnchorCrypto.certificatePem(leaf);
    } catch (GeneralSecurityException | IOException e) {
      refused(requester, request.names(), "signing failed");
      throw new AnchorStoreException(
          "a leaf could not be signed by anchor " + anchor.id() + ": " + e.getClass().getSimpleName());
    }
    String serial = leaf.getSerialNumber().toString(16);
    Instant notAfter = leaf.getNotAfter().toInstant();
    audit("ISSUED", requester, request.names(), serial, anchor.id(), notAfter, null);
    return new Leaf(
        pem, pem + anchor.certificatePem(), serial, notAfter, anchor.id(), request.names(), leaf);
  }

  /** The audit line of a caller the door refused before asking here (it lacks {@code qits:system}). */
  public void refusedAtTheDoor(String requester, String reason) {
    refused(requester, List.of(), reason);
  }

  private void refused(String requester, List<String> names, String reason) {
    audit("REFUSED", requester, names, null, null, null, reason);
  }

  private static void audit(
      String decision,
      String requester,
      List<String> names,
      String serial,
      String anchor,
      Instant notAfter,
      String reason) {
    AUDIT.infof(
        "certificates decision=%s requester=%s names=%s serial=%s anchor=%s notAfter=%s reason=%s",
        decision,
        orDash(LeafPolicy.printable(requester)),
        names.isEmpty() ? "-" : String.join(",", names),
        orDash(serial),
        orDash(anchor),
        notAfter == null ? "-" : notAfter.toString(),
        orDash(reason));
  }

  private static String orDash(String value) {
    return value == null || value.isEmpty() ? "-" : value;
  }
}
