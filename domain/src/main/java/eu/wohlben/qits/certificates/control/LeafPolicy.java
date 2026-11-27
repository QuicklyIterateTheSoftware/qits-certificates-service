package eu.wohlben.qits.certificates.control;

import java.io.IOException;
import java.io.StringReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * <b>What a leaf may be</b>: who may ask, what a CSR must be, which names it may carry, and how long
 * the leaf lives.
 *
 * <ul>
 *   <li><b>Requester:</b> the caller's {@code sub} is in {@code qits.certificates.leaf.requesters}.
 *   <li><b>CSR:</b> one PKCS#10 PEM whose signature verifies, over an EC P-256 key or an RSA key of
 *       at least 2048 bits. Its subject is ignored.
 *   <li><b>Names:</b> the subjectAltName of its extensionRequest; only dNSName, 1 to {@value
 *       #MAX_NAMES} of them (duplicates folded), each a valid hostname, lower-cased. Refused: a
 *       wildcard, an IP address, {@code localhost}, a single label, a name under {@code .internal} or
 *       {@code .local}, and {@code qits.<domain>} or any name under it (the platform's own hosts).
 *   <li><b>Validity:</b> {@code min(now + leaf validity, the anchor's notAfter)}.
 * </ul>
 *
 * <p>Bouncy Castle only parses the CSR and verifies it through the JDK's providers ({@link
 * JcaContentVerifierProviderBuilder}); it is not registered as one.
 */
public final class LeafPolicy {

  public static final int MAX_NAMES = 10;

  /** The longest CSR PEM read; a real one is about a kilobyte. */
  public static final int MAX_CSR = 16 * 1024;

  private static final Pattern LABEL = Pattern.compile("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?");

  private static final Pattern IPV4 = Pattern.compile("[0-9]+(\\.[0-9]+){3}");

  private static final Pattern NUMERIC = Pattern.compile("[0-9]+");

  /** A CSR's key and names, once every rule held. */
  public record Request(SubjectPublicKeyInfo key, boolean rsa, List<String> names) {}

  private final Set<String> requesters;

  private final String domain;

  private final Duration validity;

  /**
   * @param requesters the {@code sub}s that may ask for a leaf; blanks are dropped
   * @param domain {@code QITS_DOMAIN}; null or blank refuses no platform host
   * @param validity the longest a leaf lives
   */
  public LeafPolicy(Collection<String> requesters, String domain, Duration validity) {
    Set<String> admitted = new LinkedHashSet<>();
    for (String requester : requesters) {
      if (requester != null && !requester.isBlank()) {
        admitted.add(requester.trim());
      }
    }
    this.requesters = Set.copyOf(admitted);
    this.domain =
        domain == null || domain.isBlank() ? null : domain.trim().toLowerCase(Locale.ROOT);
    this.validity = validity;
  }

  public Set<String> requesters() {
    return requesters;
  }

  /** {@code QITS_DOMAIN}, lower-cased; empty when none is configured. */
  public Optional<String> domain() {
    return Optional.ofNullable(domain);
  }

  public Duration validity() {
    return validity;
  }

  public boolean admits(String requester) {
    return requester != null && requesters.contains(requester);
  }

  /** {@code min(now + validity, anchorNotAfter)}. */
  public Instant notAfter(Instant now, Instant anchorNotAfter) {
    Instant wanted = now.plus(validity);
    return wanted.isAfter(anchorNotAfter) ? anchorNotAfter : wanted;
  }

  /**
   * Reads and checks a CSR.
   *
   * @throws LeafRefused {@link LeafRefused.Kind#CSR} or {@link LeafRefused.Kind#NAME}
   */
  public Request check(String pem) {
    PKCS10CertificationRequest csr = verified(pem);
    SubjectPublicKeyInfo key = csr.getSubjectPublicKeyInfo();
    boolean rsa = PKCSObjectIdentifiers.rsaEncryption.equals(key.getAlgorithm().getAlgorithm());
    List<String> names = names(csr);
    for (String name : names) {
      String why = refusal(name);
      if (why != null) {
        throw LeafRefused.name(name, why, names);
      }
    }
    return new Request(key, rsa, names);
  }

  /** A CSR's key, once the CSR parsed, its key passed and its signature verified. */
  public record CsrKey(SubjectPublicKeyInfo key, boolean rsa) {}

  /**
   * Reads a CSR for its key alone: one PKCS#10 PEM of at most {@value #MAX_CSR} characters, over an
   * EC P-256 key or an RSA key of 2048 bits or more, whose signature verifies. Its subject and its
   * extensionRequest are not read. The workload door's check (qits-2756), and the first half of
   * {@link #check}.
   *
   * @throws LeafRefused {@link LeafRefused.Kind#CSR}
   */
  public static CsrKey key(String pem) {
    PKCS10CertificationRequest csr = verified(pem);
    SubjectPublicKeyInfo key = csr.getSubjectPublicKeyInfo();
    return new CsrKey(
        key, PKCSObjectIdentifiers.rsaEncryption.equals(key.getAlgorithm().getAlgorithm()));
  }

  private static PKCS10CertificationRequest verified(String pem) {
    if (pem == null || pem.isBlank()) {
      throw LeafRefused.csr("the request carries no csr");
    }
    if (pem.length() > MAX_CSR) {
      throw LeafRefused.csr("the csr is longer than " + MAX_CSR + " characters");
    }
    PKCS10CertificationRequest csr = parse(pem);
    SubjectPublicKeyInfo key = csr.getSubjectPublicKeyInfo();
    checkKey(key);
    verify(csr, key);
    return csr;
  }

  private static PKCS10CertificationRequest parse(String pem) {
    Object parsed;
    try (PEMParser parser = new PEMParser(new StringReader(pem))) {
      parsed = parser.readObject();
    } catch (IOException | RuntimeException e) {
      throw LeafRefused.csr("the csr is not a PKCS#10 PEM");
    }
    if (!(parsed instanceof PKCS10CertificationRequest csr)) {
      throw LeafRefused.csr("the csr is not a PKCS#10 PEM");
    }
    return csr;
  }

  /** True for RSA; refuses anything but EC P-256 and RSA of 2048 bits or more. */
  private static boolean checkKey(SubjectPublicKeyInfo key) {
    ASN1ObjectIdentifier algorithm = key.getAlgorithm().getAlgorithm();
    if (X9ObjectIdentifiers.id_ecPublicKey.equals(algorithm)) {
      ASN1Encodable curve = key.getAlgorithm().getParameters();
      if (!X9ObjectIdentifiers.prime256v1.equals(curve)) {
        throw LeafRefused.csr("the key is EC on a curve other than P-256");
      }
      return false;
    }
    if (PKCSObjectIdentifiers.rsaEncryption.equals(algorithm)) {
      int bits;
      try {
        bits = RSAPublicKey.getInstance(key.parsePublicKey()).getModulus().bitLength();
      } catch (IOException | RuntimeException e) {
        throw LeafRefused.csr("the RSA key is malformed");
      }
      if (bits < 2048) {
        throw LeafRefused.csr("the RSA key has " + bits + " bits, fewer than 2048");
      }
      return true;
    }
    throw LeafRefused.csr("the key is neither EC P-256 nor RSA");
  }

  private static void verify(PKCS10CertificationRequest csr, SubjectPublicKeyInfo key) {
    boolean valid;
    try {
      valid = csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(key));
    } catch (Exception e) {
      valid = false;
    }
    if (!valid) {
      throw LeafRefused.csr("the csr's signature does not verify");
    }
  }

  /** The dNSNames of the extensionRequest's subjectAltName, lower-cased, duplicates folded. */
  private static List<String> names(PKCS10CertificationRequest csr) {
    Attribute[] requests = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
    if (requests.length == 0) {
      throw LeafRefused.csr("the csr requests no names");
    }
    if (requests.length > 1 || requests[0].getAttrValues().size() != 1) {
      throw LeafRefused.csr("the csr carries more than one extensionRequest");
    }
    GeneralNames sans;
    try {
      Extensions extensions = Extensions.getInstance(requests[0].getAttrValues().getObjectAt(0));
      sans = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
    } catch (RuntimeException e) {
      throw LeafRefused.csr("the csr's extensionRequest is malformed");
    }
    if (sans == null || sans.getNames().length == 0) {
      throw LeafRefused.csr("the csr requests no names");
    }
    Set<String> names = new LinkedHashSet<>();
    List<String> refusedAddresses = new ArrayList<>();
    for (GeneralName san : sans.getNames()) {
      switch (san.getTagNo()) {
        case GeneralName.dNSName ->
            names.add(
                printable(ASN1IA5String.getInstance(san.getName()).getString())
                    .toLowerCase(Locale.ROOT));
        case GeneralName.iPAddress -> {
          String address = address(san);
          names.add(address);
          refusedAddresses.add(address);
        }
        default -> throw LeafRefused.csr("the csr requests a name that is not a dNSName");
      }
    }
    List<String> all = List.copyOf(names);
    if (all.size() > MAX_NAMES) {
      throw LeafRefused.csr("the csr requests " + all.size() + " names, more than " + MAX_NAMES, all);
    }
    if (!refusedAddresses.isEmpty()) {
      throw LeafRefused.name(refusedAddresses.get(0), "an IP address", all);
    }
    return all;
  }

  private static String address(GeneralName san) {
    byte[] bytes = ASN1OctetString.getInstance(san.getName()).getOctets();
    try {
      return InetAddress.getByAddress(bytes).getHostAddress();
    } catch (UnknownHostException e) {
      return "an IP address of " + bytes.length + " bytes";
    }
  }

  /**
   * Why {@code name} (lower-cased) may not be in a leaf, as the end of "name refused: {@code name}
   * is …"; null when it may.
   */
  public String refusal(String name) {
    if (name.contains("*")) {
      return "a wildcard";
    }
    if (name.contains(":") || IPV4.matcher(name).matches()) {
      return "an IP address";
    }
    if (name.equals("localhost") || name.endsWith(".localhost")) {
      return "localhost";
    }
    if (!name.contains(".")) {
      return "a single-label name";
    }
    if (!validHostname(name)) {
      return "not a valid hostname";
    }
    if (name.endsWith(".internal")) {
      return "under .internal";
    }
    if (name.endsWith(".local")) {
      return "under .local";
    }
    if (domain != null) {
      String platform = "qits." + domain;
      if (name.equals(platform) || name.endsWith("." + platform)) {
        return "a platform host under " + platform;
      }
    }
    return null;
  }

  private static boolean validHostname(String name) {
    if (name.length() > 253) {
      return false;
    }
    String[] labels = name.split("\\.", -1);
    for (String label : labels) {
      if (!LABEL.matcher(label).matches()) {
        return false;
      }
    }
    // A numeric top label is an address, never a domain.
    return !NUMERIC.matcher(labels[labels.length - 1]).matches();
  }

  /**
   * {@code value} safe to answer and log: anything outside printable ASCII becomes {@code ?}, and
   * it is cut at 255 characters. A CSR's names are the caller's text; they never reach a log line
   * or an answer otherwise.
   */
  public static String printable(String value) {
    if (value == null) {
      return null;
    }
    StringBuilder out = new StringBuilder(Math.min(value.length(), 255));
    for (int i = 0; i < value.length() && out.length() < 255; i++) {
      char c = value.charAt(i);
      out.append(c > 0x20 && c < 0x7f ? c : '?');
    }
    return out.toString();
  }
}
