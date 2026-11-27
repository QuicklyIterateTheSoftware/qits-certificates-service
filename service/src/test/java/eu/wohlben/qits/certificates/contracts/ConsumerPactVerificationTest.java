package eu.wohlben.qits.certificates.contracts;

import static org.junit.jupiter.api.Assertions.fail;

import au.com.dius.pact.core.model.Interaction;
import au.com.dius.pact.core.model.Pact;
import au.com.dius.pact.core.model.ProviderState;
import au.com.dius.pact.provider.junit5.HttpTestTarget;
import au.com.dius.pact.provider.junit5.PactVerificationContext;
import au.com.dius.pact.provider.junit5.PactVerificationInvocationContextProvider;
import au.com.dius.pact.provider.junitsupport.IgnoreNoPactsToVerify;
import au.com.dius.pact.provider.junitsupport.Provider;
import au.com.dius.pact.provider.junitsupport.State;
import au.com.dius.pact.provider.junitsupport.loader.PactSource;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.net.URL;
import java.util.List;
import java.util.Map;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * <b>Verifies every consumer's pact against the running qits-certificates</b>, the way
 * qits-agents-service does.
 *
 * <p>Each consumer publishes its pact as a jar holding {@code
 * pacts/<consumer>_qits-certificates-service.json}; this repository pins the jar as a test
 * dependency and {@link ClasspathPactLoader} finds it. <b>No consumer pins one yet</b> (qits-2632's
 * trust-anchors client will be the first), so this class carries {@link IgnoreNoPactsToVerify} and
 * {@link ClasspathPactLoader#REQUIRED} is false; drop the one and flip the other when the first jar
 * is pinned.
 *
 * <p>An interaction that carries no {@code Authorization} runs as its state's caller ({@link
 * ProviderStates.Setup#caller()}): the operator holding {@code qits:admin} in the anchors states
 * (the anchors read needs none; the rotation needs it), the leaf requester or a {@code qits:system}
 * service that is not one in the leaf states, qits-edge's service token or a person's token in the
 * workload states. Every {@code @State} method
 * delegates to {@link ProviderStates}; {@link #target} fails an unknown state, and an interaction
 * without {@code comments.references.qits-call} or {@code qits-trigger}.
 */
@QuarkusTest
@Provider(ConsumerPactVerificationTest.PROVIDER)
@PactSource(ClasspathPactLoader.class)
@IgnoreNoPactsToVerify
class ConsumerPactVerificationTest {

  /** The provider's name in a pact: the repository name, not the application name. */
  static final String PROVIDER = "qits-certificates-service";

  static {
    // pact-jvm reports usage metrics over the network unless told not to; a test never should.
    System.setProperty("pact_do_not_track", "true");
  }

  @Inject ProviderStates states;

  @TestHTTPResource("/")
  URL base;

  @BeforeEach
  void target(PactVerificationContext context, Pact pact, Interaction interaction) {
    if (context == null) {
      return; // No pact: nothing to target.
    }
    String consumer = pact.getConsumer().getName();
    for (ProviderState state : interaction.getProviderStates()) {
      if (!states.names().contains(state.getName())) {
        fail(
            "Consumer '"
                + consumer
                + "' needs the provider state '"
                + state.getName()
                + "' (interaction '"
                + interaction.getDescription()
                + "'), which qits-certificates does not answer for — it answers for "
                + states.names());
      }
    }
    var references = interaction.getComments().get("references");
    for (String key : List.of("qits-call", "qits-trigger")) {
      if (references == null || !references.isObject() || !references.asObject().has(key)) {
        fail(
            "Consumer '"
                + consumer
                + "' interaction '"
                + interaction.getDescription()
                + "' carries no comments.references."
                + key);
      }
    }
    context.setTarget(new HttpTestTarget(base.getHost(), base.getPort()));
  }

  @TestTemplate
  @ExtendWith(PactVerificationInvocationContextProvider.class)
  void consumerPactHolds(PactVerificationContext context, ClassicHttpRequest request) {
    if (context == null) {
      return;
    }
    if (request != null && !request.containsHeader("Authorization")) {
      request.setHeader("Authorization", states.caller().authorization());
    }
    try {
      context.verifyInteraction();
    } finally {
      states.reset();
    }
  }

  // --- the states: each one line into the registry -------------------------------------------

  @State(ProviderStates.ONE_ACTIVE_ANCHOR)
  Map<String, String> oneActiveAnchor() {
    return states.params(ProviderStates.ONE_ACTIVE_ANCHOR);
  }

  @State(ProviderStates.ONE_ACTIVE_AND_ONE_PENDING_ANCHOR)
  Map<String, String> oneActiveAndOnePendingAnchor() {
    return states.params(ProviderStates.ONE_ACTIVE_AND_ONE_PENDING_ANCHOR);
  }

  @State(ProviderStates.LEAF_ISSUED)
  Map<String, String> leafIssued() {
    return states.params(ProviderStates.LEAF_ISSUED);
  }

  @State(ProviderStates.LEAF_NAME_REFUSED)
  Map<String, String> leafNameRefused() {
    return states.params(ProviderStates.LEAF_NAME_REFUSED);
  }

  @State(ProviderStates.NOT_A_LEAF_REQUESTER)
  Map<String, String> notALeafRequester() {
    return states.params(ProviderStates.NOT_A_LEAF_REQUESTER);
  }

  @State(ProviderStates.WORKLOAD_CERTIFICATE_ISSUED)
  Map<String, String> workloadCertificateIssued() {
    return states.params(ProviderStates.WORKLOAD_CERTIFICATE_ISSUED);
  }

  @State(ProviderStates.WORKLOAD_CERTIFICATE_REFUSED)
  Map<String, String> workloadCertificateRefused() {
    return states.params(ProviderStates.WORKLOAD_CERTIFICATE_REFUSED);
  }

  @State(ProviderStates.WORKLOAD_CSR_REFUSED)
  Map<String, String> workloadCsrRefused() {
    return states.params(ProviderStates.WORKLOAD_CSR_REFUSED);
  }
}
