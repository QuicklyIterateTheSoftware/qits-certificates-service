package eu.wohlben.qits.certificates.control;

import java.util.List;

/**
 * A leaf was refused, and why. The door answers 403 for {@link Kind#NOT_REQUESTER} and 400 for the
 * other two; the audit line carries {@link #reason()}. No message ever quotes the CSR, only names it
 * asked for, made printable ({@link LeafPolicy#printable(String)}).
 */
public class LeafRefused extends RuntimeException {

  public enum Kind {
    /** The caller's {@code sub} is not in {@code qits.certificates.leaf.requesters}. */
    NOT_REQUESTER,
    /** One requested name breaks a name rule; {@link #name()} is it. */
    NAME,
    /** The CSR itself: unparseable, a bad signature, a key it does not take, no or too many names. */
    CSR
  }

  private final Kind kind;

  private final String name;

  private final String reason;

  private final List<String> names;

  private LeafRefused(Kind kind, String name, String reason, List<String> names) {
    super(reason, null, false, false);
    this.kind = kind;
    this.name = name;
    this.reason = reason;
    this.names = List.copyOf(names);
  }

  public static LeafRefused notRequester() {
    return new LeafRefused(Kind.NOT_REQUESTER, null, "not a leaf requester", List.of());
  }

  static LeafRefused name(String name, String why, List<String> names) {
    return new LeafRefused(Kind.NAME, name, "name refused: " + name + " is " + why, names);
  }

  static LeafRefused csr(String reason) {
    return new LeafRefused(Kind.CSR, null, reason, List.of());
  }

  static LeafRefused csr(String reason, List<String> names) {
    return new LeafRefused(Kind.CSR, null, reason, names);
  }

  public Kind kind() {
    return kind;
  }

  /** The refused name, printable; null unless {@link Kind#NAME}. */
  public String name() {
    return name;
  }

  /** What the audit line and a 400 say. */
  public String reason() {
    return reason;
  }

  /** Every name the CSR asked for, as far as it was read; empty when it was not. */
  public List<String> names() {
    return names;
  }
}
