package eu.wohlben.qits.certificates.contracts;

import eu.wohlben.qits.certificates.api.Roles;
import eu.wohlben.qits.certificates.support.Ca;
import eu.wohlben.qits.certificates.support.TestEntropy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Supplier;

/**
 * <b>qits-certificates' provider states</b>: each one wipes the CA volume, stages the fixed
 * fixture anchors ({@link Ca}) with the clock pinned, and hands back its parameters. Two callers:
 * {@link GoldenMasterRecordingTest} runs a state before each operation that names it, and {@link
 * ConsumerPactVerificationTest}'s {@code @State} methods delegate here.
 *
 * <p>Every state starts from an empty volume, so applying it twice is the same state, and the
 * anchors it stages are the same bytes on every run.
 *
 * <p>The three leaf states stage the ACTIVE fixture anchor and pin the leaf randomness ({@link
 * TestEntropy}) as well as the clock, so a leaf issued in them is the same bytes on every run. Each
 * also names the caller ({@link Setup#caller()}) a call without its own {@code Authorization} is
 * made as: the leaf requester, or a {@code qits:system} service that is not one.
 */
@ApplicationScoped
public class ProviderStates {

  /** The anchor the service signs with, alone. */
  public static final String ONE_ACTIVE_ANCHOR = "one ACTIVE anchor";

  /** A rotation under way: the ACTIVE anchor and the PENDING one that will replace it. */
  public static final String ONE_ACTIVE_AND_ONE_PENDING_ANCHOR = "one ACTIVE and one PENDING anchor";

  /** A leaf requester asks for a leaf the rules allow. */
  public static final String LEAF_ISSUED = "leaf issued";

  /** A leaf requester asks for a leaf with a name the rules refuse. */
  public static final String LEAF_NAME_REFUSED = "leaf name refused";

  /** A {@code qits:system} service that is not a leaf requester asks for a leaf. */
  public static final String NOT_A_LEAF_REQUESTER = "not a leaf requester";

  /** Who the operator recordings call as. */
  public static final String OPERATOR = "operator";

  /** The leaf requester the suite configures ({@code %test.qits.certificates.leaf.requesters}). */
  public static final String REQUESTER = "dev-qits-egress";

  /** A {@code qits:system} service that is not a leaf requester. */
  public static final String NOT_A_REQUESTER = "dev-qits-ci";

  /** Who calls: a {@code sub} and the roles it holds. */
  public record Caller(String subject, List<String> roles) {}

  /** The operator holding {@code qits:admin}, the caller of every anchors state. */
  public static final Caller OPERATOR_CALLER = new Caller(OPERATOR, List.of(Roles.ADMIN));

  /**
   * What a state hands back: its parameters, keys sorted, no unique tokens, and the caller a call
   * without its own {@code Authorization} is made as.
   */
  public record Setup(Map<String, String> params, Caller caller) {
    public List<String> uniqueTokens() {
      return List.of();
    }
  }

  private final Map<String, Supplier<Setup>> states = new LinkedHashMap<>();

  @Inject Ca ca;

  @Inject TestEntropy entropy;

  private volatile Caller caller = OPERATOR_CALLER;

  public ProviderStates() {
    states.put(ONE_ACTIVE_ANCHOR, this::oneActiveAnchor);
    states.put(ONE_ACTIVE_AND_ONE_PENDING_ANCHOR, this::oneActiveAndOnePendingAnchor);
    states.put(LEAF_ISSUED, () -> leafState(REQUESTER));
    states.put(LEAF_NAME_REFUSED, () -> leafState(REQUESTER));
    states.put(NOT_A_LEAF_REQUESTER, () -> leafState(NOT_A_REQUESTER));
  }

  /** The caller of the state set up last. */
  public Caller caller() {
    return caller;
  }

  /** Unpins what the states pinned beyond the clock: the leaf randomness. */
  public void reset() {
    entropy.reset();
    caller = OPERATOR_CALLER;
  }

  public Set<String> names() {
    return Collections.unmodifiableSet(states.keySet());
  }

  public Setup setUp(String state) {
    Supplier<Setup> setup = states.get(state);
    if (setup == null) {
      throw new IllegalArgumentException(
          "No provider state '" + state + "' — this provider answers for " + states.keySet());
    }
    Setup done = setup.get();
    caller = done.caller();
    return done;
  }

  public Map<String, String> params(String state) {
    return setUp(state).params();
  }

  /** The state's slug: lower-cased, every run of non-alphanumerics replaced by {@code -}. */
  public static String slug(String state) {
    return state.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-");
  }

  // --- the states ------------------------------------------------------------------------------

  private Setup oneActiveAnchor() {
    ca.stage(Ca.ACTIVE);
    Map<String, String> params = new TreeMap<>();
    params.put("activeAnchorId", Ca.ACTIVE);
    entropy.reset();
    return new Setup(Collections.unmodifiableMap(params), OPERATOR_CALLER);
  }

  private Setup oneActiveAndOnePendingAnchor() {
    ca.stage(Ca.ACTIVE, Ca.PENDING);
    Map<String, String> params = new TreeMap<>();
    params.put("activeAnchorId", Ca.ACTIVE);
    params.put("pendingAnchorId", Ca.PENDING);
    entropy.reset();
    return new Setup(Collections.unmodifiableMap(params), OPERATOR_CALLER);
  }

  /** The ACTIVE fixture anchor, the clock and the leaf randomness pinned, {@code subject} calling. */
  private Setup leafState(String subject) {
    ca.stage(Ca.ACTIVE);
    entropy.pin();
    Map<String, String> params = new TreeMap<>();
    params.put("activeAnchorId", Ca.ACTIVE);
    return new Setup(Collections.unmodifiableMap(params), new Caller(subject, List.of(Roles.SYSTEM)));
  }
}
