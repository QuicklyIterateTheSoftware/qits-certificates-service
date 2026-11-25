package eu.wohlben.qits.certificates.control;

/**
 * Where an anchor is in its life. Every status but {@link #RETIRED} is in the published bundle;
 * only {@link #ACTIVE} signs leaves, and exactly one anchor is ACTIVE when the service is ready.
 */
public enum AnchorStatus {
  /** Published so containers learn it before it signs; becomes ACTIVE at {@code activatesAt}. */
  PENDING,
  /** The one anchor that signs leaves. */
  ACTIVE,
  /** Still published while the leaves it signed live; RETIRED at {@code retiresAt}. */
  RETIRING,
  /** Out of the bundle; its {@code key.pem} is deleted and its {@code cert.pem} kept. */
  RETIRED
}
