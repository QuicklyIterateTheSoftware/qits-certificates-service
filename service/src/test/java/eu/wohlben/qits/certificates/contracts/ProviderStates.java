package eu.wohlben.qits.certificates.contracts;

import eu.wohlben.qits.certificates.support.Ca;
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
 */
@ApplicationScoped
public class ProviderStates {

  /** The anchor the service signs with, alone. */
  public static final String ONE_ACTIVE_ANCHOR = "one ACTIVE anchor";

  /** A rotation under way: the ACTIVE anchor and the PENDING one that will replace it. */
  public static final String ONE_ACTIVE_AND_ONE_PENDING_ANCHOR = "one ACTIVE and one PENDING anchor";

  /** Who the operator recordings call as. */
  public static final String OPERATOR = "operator";

  /** What a state hands back: its parameters, keys sorted, and no unique tokens. */
  public record Setup(Map<String, String> params) {
    public List<String> uniqueTokens() {
      return List.of();
    }
  }

  private final Map<String, Supplier<Setup>> states = new LinkedHashMap<>();

  @Inject Ca ca;

  public ProviderStates() {
    states.put(ONE_ACTIVE_ANCHOR, this::oneActiveAnchor);
    states.put(ONE_ACTIVE_AND_ONE_PENDING_ANCHOR, this::oneActiveAndOnePendingAnchor);
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
    return setup.get();
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
    return new Setup(Collections.unmodifiableMap(params));
  }

  private Setup oneActiveAndOnePendingAnchor() {
    ca.stage(Ca.ACTIVE, Ca.PENDING);
    Map<String, String> params = new TreeMap<>();
    params.put("activeAnchorId", Ca.ACTIVE);
    params.put("pendingAnchorId", Ca.PENDING);
    return new Setup(Collections.unmodifiableMap(params));
  }
}
