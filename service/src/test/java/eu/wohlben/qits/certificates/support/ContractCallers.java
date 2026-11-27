package eu.wohlben.qits.certificates.support;

import io.quarkus.arc.Arc;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import org.eclipse.microprofile.jwt.JsonWebToken;

/**
 * <b>The callers a suite names by their {@code Authorization} value</b> (qits-agents-service's
 * shape): the {@code %test} suite runs no idp, so an {@code Authorization} header means nothing
 * until it is granted here. {@link #caller} grants a named caller holding roles; its scheme is
 * {@code Suite}, never {@code Bearer}. Tried before the shipped mechanisms; a request whose value
 * nobody granted is left alone, and is anonymous with the OIDC tenant off.
 *
 * <p>{@link #token} grants a caller whose principal is a {@link JsonWebToken} carrying the given
 * claims, as quarkus-oidc leaves it: the workload door (qits-2756) decides from claims, not roles.
 */
@ApplicationScoped
public class ContractCallers implements HttpAuthenticationMechanism {

  static final String SCHEME = "Suite ";

  record Grant(String subject, Set<String> roles, Map<String, Object> claims) {}

  private static final AtomicLong TOKENS = new AtomicLong();

  private final Map<String, Grant> grants = new ConcurrentHashMap<>();

  /** The {@code Authorization} value of {@code subject} holding {@code roles}. */
  public static String caller(String subject, String... roles) {
    String authorization = SCHEME + subject + "." + String.join("+", roles);
    // Through a method: the bean is a client proxy, whose own fields are not the instance's.
    Arc.container()
        .instance(ContractCallers.class)
        .get()
        .grant(authorization, new Grant(subject, Set.of(roles), null));
    return authorization;
  }

  /**
   * The {@code Authorization} value of a token carrying {@code claims} (its {@code sub} among them)
   * and holding {@code roles}. Each call grants a value of its own.
   */
  public static String token(Map<String, Object> claims, String... roles) {
    String subject = String.valueOf(claims.get("sub"));
    String authorization = SCHEME + "jwt-" + TOKENS.incrementAndGet() + "." + subject;
    Arc.container()
        .instance(ContractCallers.class)
        .get()
        .grant(authorization, new Grant(subject, Set.of(roles), new LinkedHashMap<>(claims)));
    return authorization;
  }

  void grant(String authorization, Grant grant) {
    grants.put(authorization, grant);
  }

  @Override
  public Uni<SecurityIdentity> authenticate(
      RoutingContext context, IdentityProviderManager identityProviderManager) {
    String authorization = context.request().getHeader("Authorization");
    Grant grant = authorization == null ? null : grants.get(authorization);
    if (grant == null) {
      return Uni.createFrom().optional(Optional.empty());
    }
    QuarkusSecurityIdentity.Builder identity =
        QuarkusSecurityIdentity.builder()
            .setPrincipal(
                grant.claims() == null
                    ? new QuarkusPrincipal(grant.subject())
                    : new SuiteJwt(grant.subject(), grant.claims()));
    grant.roles().forEach(identity::addRole);
    return Uni.createFrom().item(identity.build());
  }

  @Override
  public Uni<ChallengeData> getChallenge(RoutingContext context) {
    return Uni.createFrom().optional(Optional.empty());
  }

  @Override
  public Set<Class<? extends AuthenticationRequest>> getCredentialTypes() {
    return Set.of();
  }

  @Override
  public int getPriority() {
    return DEFAULT_PRIORITY + 1000;
  }

  /** A validated token's principal, as far as a door reads one: its name and its claims. */
  record SuiteJwt(String name, Map<String, Object> claims) implements JsonWebToken {

    @Override
    public String getName() {
      return name;
    }

    @Override
    public Set<String> getClaimNames() {
      return claims.keySet();
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T getClaim(String claimName) {
      return (T) claims.get(claimName);
    }
  }
}
