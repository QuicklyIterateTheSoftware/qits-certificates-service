package eu.wohlben.qits.certificates.contracts;

import eu.wohlben.qits.certificates.api.Roles;
import eu.wohlben.qits.certificates.support.Ca;
import eu.wohlben.qits.certificates.support.ContractCallers;
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

  /** qits-edge's own service client asks for its workload certificate (qits-2756). */
  public static final String WORKLOAD_CERTIFICATE_ISSUED = "workload certificate issued";

  /** A person's token asks for a workload certificate, which only workloads get. */
  public static final String WORKLOAD_CERTIFICATE_REFUSED = "workload certificate refused";

  /** A workload sends something that is not a CSR. */
  public static final String WORKLOAD_CSR_REFUSED = "workload csr refused";

  /** The service client the workload states call as: qits-edge in the suite's environment. */
  public static final Caller WORKLOAD_SERVICE =
      new Caller(
          "dev-qits-edge",
          List.of(Roles.SYSTEM),
          Map.of(
              "sub", "dev-qits-edge",
              "groups", List.of("qits:system", "clients/dev-qits-edge"),
              "project", "*"));

  /** A person signed in with the CLI. */
  public static final Caller PERSON =
      new Caller(
          "6b0c1f4e-0000-4000-8000-00000000000a",
          List.of(Roles.ADMIN),
          Map.of(
              "sub", "6b0c1f4e-0000-4000-8000-00000000000a",
              "groups", List.of(Roles.ADMIN),
              "credential_type", "cli"));

  /** Who the operator recordings call as. */
  public static final String OPERATOR = "operator";

  /** The leaf requester the suite configures ({@code %test.qits.certificates.leaf.requesters}). */
  public static final String REQUESTER = "dev-qits-egress";

  /** A {@code qits:system} service that is not a leaf requester. */
  public static final String NOT_A_REQUESTER = "dev-qits-ci";

  /**
   * Who calls: a {@code sub}, the roles it holds and, for a door that reads them, its token's
   * claims (null: a principal with no claims, as every leaf and anchors state has).
   */
  public record Caller(String subject, List<String> roles, Map<String, Object> claims) {

    public Caller(String subject, List<String> roles) {
      this(subject, roles, null);
    }

    /** The {@code Authorization} value this caller sends ({@link ContractCallers}). */
    public String authorization() {
      String[] held = roles.toArray(String[]::new);
      return claims == null
          ? ContractCallers.caller(subject, held)
          : ContractCallers.token(claims, held);
    }
  }

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
    states.put(WORKLOAD_CERTIFICATE_ISSUED, () -> pinnedAnchor(WORKLOAD_SERVICE));
    states.put(WORKLOAD_CERTIFICATE_REFUSED, () -> pinnedAnchor(PERSON));
    states.put(WORKLOAD_CSR_REFUSED, () -> pinnedAnchor(WORKLOAD_SERVICE));
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
    return pinnedAnchor(new Caller(subject, List.of(Roles.SYSTEM)));
  }

  /** The ACTIVE fixture anchor, the clock and the randomness pinned, {@code caller} calling. */
  private Setup pinnedAnchor(Caller caller) {
    ca.stage(Ca.ACTIVE);
    entropy.pin();
    Map<String, String> params = new TreeMap<>();
    params.put("activeAnchorId", Ca.ACTIVE);
    return new Setup(Collections.unmodifiableMap(params), caller);
  }
}
