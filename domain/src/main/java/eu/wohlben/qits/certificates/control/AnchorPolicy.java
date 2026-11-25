package eu.wohlben.qits.certificates.control;

import java.time.Duration;
import java.util.Objects;

/**
 * The anchor parameters, from configuration ({@code qits.certificates.*}).
 *
 * @param environment the environment in the anchor's subject ({@code QITS_ENVIRONMENT})
 * @param validity how long a new anchor's certificate is valid ({@code anchor.validity}, P1826D)
 * @param overlap how long a PENDING anchor is published before it becomes ACTIVE ({@code
 *     anchor.overlap}, P30D)
 * @param renewBefore how long before the ACTIVE anchor's {@code notAfter} a rotation starts
 *     ({@code anchor.renew-before}, P365D)
 * @param leafValidity the longest a leaf lives ({@code leaf.validity}, P7D): a RETIRING anchor
 *     stays in the bundle for that plus a day
 */
public record AnchorPolicy(
    String environment,
    Duration validity,
    Duration overlap,
    Duration renewBefore,
    Duration leafValidity) {

  /** The production defaults, for {@code environment}. */
  public static AnchorPolicy defaults(String environment) {
    return new AnchorPolicy(
        environment,
        Duration.ofDays(1826),
        Duration.ofDays(30),
        Duration.ofDays(365),
        Duration.ofDays(7));
  }

  public AnchorPolicy {
    Objects.requireNonNull(environment, "environment");
    Objects.requireNonNull(validity, "validity");
    Objects.requireNonNull(overlap, "overlap");
    Objects.requireNonNull(renewBefore, "renewBefore");
    Objects.requireNonNull(leafValidity, "leafValidity");
  }

  /** How long a RETIRING anchor stays published: the leaf validity plus one day. */
  public Duration retiringFor() {
    return leafValidity.plusDays(1);
  }
}
