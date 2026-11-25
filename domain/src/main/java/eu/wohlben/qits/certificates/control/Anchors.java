package eu.wohlben.qits.certificates.control;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * <b>The platform's trust anchors</b>: loaded from {@code <ca-dir>/anchors/} ({@link AnchorStore}),
 * moved through PENDING → ACTIVE → RETIRING → RETIRED by {@link #tick()}, and published as {@link
 * #bundle()}.
 *
 * <ul>
 *   <li><b>First boot</b> (no anchor): one ACTIVE anchor is made at once.
 *   <li><b>Rotation start</b>: a PENDING anchor with {@code activatesAt = now + overlap}, by {@link
 *       #rotate()} (the admin door) or by {@link #tick()} once the ACTIVE anchor's {@code notAfter}
 *       is less than {@code renew-before} away. Never more than one PENDING.
 *   <li><b>Activation</b>: a PENDING anchor whose {@code activatesAt} has passed becomes ACTIVE, and
 *       the previous ACTIVE one RETIRING with {@code retiresAt = now + leaf validity + P1D}. The old
 *       one is demoted first: a crash in between leaves no ACTIVE anchor and a PENDING one, which
 *       the next tick activates, rather than two ACTIVE ones.
 *   <li><b>Retirement</b>: a RETIRING anchor whose {@code retiresAt} has passed becomes RETIRED;
 *       its {@code key.pem} is deleted, its {@code cert.pem} kept.
 * </ul>
 *
 * <p>Time is the injected {@link Clock}, so a test drives the whole path. Every write is
 * serialised on this object; reads take the last published snapshot and never wait.
 */
@Singleton
public class Anchors {

  private static final Logger LOG = Logger.getLogger(Anchors.class);

  /** The bundle's order: ACTIVE first, then PENDING, then RETIRING. */
  private static final List<AnchorStatus> PUBLISHED =
      List.of(AnchorStatus.ACTIVE, AnchorStatus.PENDING, AnchorStatus.RETIRING);

  /**
   * What is published: the anchors in bundle order, their certificates as one PEM text, and its
   * version (the lower-case hex SHA-256 of that text).
   */
  public record Bundle(List<Anchor> anchors, String pem, String version) {}

  /** The readiness verdict: up with the ACTIVE anchor, or down with why. */
  public record Readiness(boolean up, String reason, Anchor active) {}

  private final AnchorStore store;

  private final AnchorPolicy policy;

  private final Clock clock;

  private volatile List<Anchor> anchors = List.of();

  private volatile Bundle bundle = bundleOf(List.of());

  @Inject
  public Anchors(
      @ConfigProperty(name = "qits.certificates.ca-dir", defaultValue = "/work/ca") String caDir,
      @ConfigProperty(name = "qits.certificates.environment", defaultValue = "dev") String environment,
      @ConfigProperty(name = "qits.certificates.anchor.validity", defaultValue = "P1826D")
          Duration validity,
      @ConfigProperty(name = "qits.certificates.anchor.overlap", defaultValue = "P30D")
          Duration overlap,
      @ConfigProperty(name = "qits.certificates.anchor.renew-before", defaultValue = "P365D")
          Duration renewBefore,
      @ConfigProperty(name = "qits.certificates.leaf.validity", defaultValue = "P7D")
          Duration leafValidity,
      Clock clock) {
    this(
        Path.of(caDir),
        new AnchorPolicy(environment, validity, overlap, renewBefore, leafValidity),
        clock);
  }

  public Anchors(Path caDir, AnchorPolicy policy, Clock clock) {
    this.store = new AnchorStore(caDir);
    this.policy = policy;
    this.clock = clock;
  }

  public AnchorPolicy policy() {
    return policy;
  }

  /** {@code <ca-dir>/anchors}. */
  public Path directory() {
    return store.directory();
  }

  /** Re-reads every anchor from the volume, replacing what is held. */
  public synchronized void load() {
    publish(store.load());
    LOG.infof("anchors loaded from %s: %s", store.directory(), describe(anchors));
  }

  /** At startup: {@link #load()}, then {@link #tick()}. A volume fault is logged, not thrown. */
  public synchronized void start() {
    try {
      load();
      tick();
    } catch (AnchorStoreException e) {
      LOG.errorf("the anchors could not be started: %s", e.getMessage());
    }
  }

  /**
   * One pass of the state machine at {@code clock.instant()}: first boot, activation, retirement
   * and the renew-before check, in that order.
   *
   * @throws AnchorStoreException when the volume refuses a write; what was done before stays done
   */
  public synchronized void tick() {
    Instant now = clock.instant();
    List<Anchor> held = new ArrayList<>(anchors);
    try {
      advance(now, held);
    } finally {
      // What was written stays published even when a later write failed.
      publish(held);
    }
  }

  private void advance(Instant now, List<Anchor> held) {
    Optional<Anchor> active = first(held, AnchorStatus.ACTIVE);
    Optional<Anchor> pending = first(held, AnchorStatus.PENDING);

    // No ACTIVE anchor: a PENDING one takes over at once (a crash between demotion and promotion),
    // otherwise this is the first boot.
    if (active.isEmpty() && pending.isPresent()) {
      Anchor promoted = replace(held, store.update(pending.get(), pending.get().state().activated(now)));
      LOG.infof("anchor %s is ACTIVE: there was no ACTIVE anchor", promoted.id());
      active = Optional.of(promoted);
      pending = Optional.empty();
    } else if (active.isEmpty()) {
      Anchor made = make(AnchorStatus.ACTIVE, now, now);
      held.add(made);
      LOG.infof("anchor %s made ACTIVE on first boot: %s", made.id(), made.subject());
      active = Optional.of(made);
    }

    // Activation.
    if (pending.isPresent() && !pending.get().state().activatesAt().isAfter(now)) {
      Anchor old = active.get();
      Instant retiresAt = now.plus(policy.retiringFor());
      replace(held, store.update(old, old.state().retiring(retiresAt)));
      Anchor promoted = replace(held, store.update(pending.get(), pending.get().state().activated(now)));
      LOG.infof(
          "anchor %s is ACTIVE; anchor %s is RETIRING until %s", promoted.id(), old.id(), retiresAt);
      pending = Optional.empty();
      active = Optional.of(promoted);
    }

    // Retirement, and a RETIRED key a crash left behind.
    for (Anchor anchor : List.copyOf(held)) {
      if (anchor.status() == AnchorStatus.RETIRING
          && anchor.state().retiresAt() != null
          && !anchor.state().retiresAt().isAfter(now)) {
        Anchor retired = replace(held, store.update(anchor, anchor.state().withStatus(AnchorStatus.RETIRED)));
        store.deleteKey(retired);
        LOG.infof("anchor %s is RETIRED: its key is deleted, its certificate kept", retired.id());
      } else if (anchor.status() == AnchorStatus.RETIRED && store.hasKey(anchor)) {
        store.deleteKey(anchor);
        LOG.infof("anchor %s is RETIRED: its remaining key is deleted", anchor.id());
      }
    }

    // Renew-before.
    if (pending.isEmpty()
        && Duration.between(now, active.get().state().notAfter()).compareTo(policy.renewBefore()) < 0) {
      Anchor made = make(AnchorStatus.PENDING, now, now.plus(policy.overlap()));
      held.add(made);
      LOG.infof(
          "anchor %s made PENDING, ACTIVE from %s: anchor %s expires %s",
          made.id(),
          made.state().activatesAt(),
          active.get().id(),
          active.get().state().notAfter());
    }
  }

  /**
   * Starts a rotation by hand: a new PENDING anchor, ACTIVE after the overlap.
   *
   * @throws PendingAnchorExists when one is already PENDING
   * @throws AnchorStoreException when the volume refuses the write
   */
  public synchronized Anchor rotate() {
    Optional<Anchor> pending = first(anchors, AnchorStatus.PENDING);
    if (pending.isPresent()) {
      throw new PendingAnchorExists(pending.get().id());
    }
    Instant now = clock.instant();
    Anchor made = make(AnchorStatus.PENDING, now, now.plus(policy.overlap()));
    List<Anchor> held = new ArrayList<>(anchors);
    held.add(made);
    publish(held);
    LOG.infof("anchor %s made PENDING by request, ACTIVE from %s", made.id(), made.state().activatesAt());
    return made;
  }

  /** Every anchor held, RETIRED ones included, in directory-name order. */
  public List<Anchor> all() {
    return anchors;
  }

  /** The published anchors and their PEM bundle. */
  public Bundle bundle() {
    return bundle;
  }

  /** UP when exactly one anchor is ACTIVE and its key reads back as its certificate's. */
  public Readiness readiness() {
    List<Anchor> active = anchors.stream().filter(a -> a.status() == AnchorStatus.ACTIVE).toList();
    if (active.size() != 1) {
      return new Readiness(false, active.size() + " ACTIVE anchors are loaded, not 1", null);
    }
    try {
      store.readKey(active.get(0));
      return new Readiness(true, null, active.get(0));
    } catch (AnchorStoreException e) {
      return new Readiness(false, e.getMessage(), active.get(0));
    }
  }

  /** The ACTIVE anchor's private key, for signing; read from the volume on every call. */
  public PrivateKey activeKey() {
    Anchor active =
        first(anchors, AnchorStatus.ACTIVE)
            .orElseThrow(() -> new AnchorStoreException("no anchor is ACTIVE"));
    return store.readKey(active);
  }

  private Anchor make(AnchorStatus status, Instant now, Instant activatesAt) {
    AnchorCrypto.Made made;
    String sha256;
    try {
      made = AnchorCrypto.make(policy.environment(), now, policy.validity());
      sha256 = AnchorCrypto.sha256(made.certificate());
    } catch (GeneralSecurityException e) {
      throw new AnchorStoreException("a new anchor could not be made: " + e.getMessage(), e);
    }
    AnchorState state =
        new AnchorState(
            UUID.randomUUID().toString(),
            status,
            now,
            activatesAt,
            null,
            made.certificate().getNotAfter().toInstant(),
            sha256);
    return store.create(state, made);
  }

  private void publish(List<Anchor> held) {
    List<Anchor> sorted =
        held.stream().sorted(Comparator.comparing(a -> a.directory().getFileName().toString())).toList();
    anchors = sorted;
    bundle = bundleOf(sorted);
  }

  private static Bundle bundleOf(List<Anchor> held) {
    List<Anchor> published =
        held.stream()
            .filter(a -> PUBLISHED.contains(a.status()))
            .sorted(
                Comparator.<Anchor>comparingInt(a -> PUBLISHED.indexOf(a.status()))
                    .thenComparing(a -> a.state().createdAt())
                    .thenComparing(Anchor::id))
            .toList();
    StringBuilder pem = new StringBuilder();
    published.forEach(a -> pem.append(a.certificatePem()));
    String text = pem.toString();
    return new Bundle(published, text, AnchorCrypto.sha256(text.getBytes(StandardCharsets.US_ASCII)));
  }

  private static Optional<Anchor> first(List<Anchor> held, AnchorStatus status) {
    return held.stream()
        .filter(a -> a.status() == status)
        .min(Comparator.comparing((Anchor a) -> a.state().createdAt()).thenComparing(Anchor::id));
  }

  /** Puts {@code next} where the anchor with its id was; returns it. */
  private static Anchor replace(List<Anchor> held, Anchor next) {
    for (int i = 0; i < held.size(); i++) {
      if (held.get(i).id().equals(next.id())) {
        held.set(i, next);
        return next;
      }
    }
    held.add(next);
    return next;
  }

  private static String describe(List<Anchor> held) {
    if (held.isEmpty()) {
      return "none";
    }
    return String.join(", ", held.stream().map(a -> a.id() + " " + a.status()).toList());
  }
}
