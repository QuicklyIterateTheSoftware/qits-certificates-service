package eu.wohlben.qits.certificates.api;

/**
 * The roles the doors name, as constants the {@code @RolesAllowed} lists spell out.
 *
 * <ul>
 *   <li>{@code GET /anchors} is {@code @PermitAll}: the bundle is public by nature, and every
 *       container fetches it before it holds any credential.
 *   <li>{@code POST /anchors/rotate}: {@code qits:admin} alone.
 *   <li>{@code POST /leaves}: {@code qits:system}, and then the caller's {@code sub} must be in
 *       {@code qits.certificates.leaf.requesters}.
 * </ul>
 *
 * <p>DeskAdminParityRules holds over every door: wherever {@code qits:admin-agent} is admitted, so
 * is {@code qits:desk-admin}. No door here admits either.
 */
public final class Roles {

  public static final String ADMIN = "qits:admin";

  public static final String SYSTEM = "qits:system";

  private Roles() {}
}
