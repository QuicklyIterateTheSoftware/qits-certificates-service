package eu.wohlben.qits.certificates.control;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/**
 * The whole crypto path of this service, once, in memory: the proof that Bouncy Castle's bcpkix
 * works in the packaged artifact — the native image above all, where a lost registration breaks
 * with a green JVM suite (qits-2646).
 *
 * <p>It makes an EC P-384 anchor and self-signs it with {@code SHA384withECDSA}, round-trips it
 * through PEM, then signs an EC P-256 CSR end to end: the CSR is built with a {@code dNSName}
 * extension request, PEM-encoded, parsed back, its signature verified, and a leaf issued from it
 * and verified against the anchor. Every key and every signature is the JDK's default provider
 * (SunEC); Bouncy Castle only builds and parses the structures. Nothing is written anywhere and no
 * key leaves the method: the result carries names and serial lengths only.
 *
 * <p>The real certificate authority (anchors on {@code /work/ca}, the leaf policy) replaces this as
 * its own code in C2; the readiness check that runs this stays until then.
 */
public final class CertificateSmoke {

  /** The name the smoke's leaf asks for: never a platform host, and never issued for real. */
  public static final String LEAF_NAME = "smoke.certificates.invalid";

  private static final SecureRandom RANDOM = new SecureRandom();

  /** What the smoke proved, without any key material. */
  public record Result(String anchorSubject, String leafSubject, List<String> leafNames) {}

  private CertificateSmoke() {}

  /**
   * Runs the smoke.
   *
   * @return the anchor's and the leaf's subjects and the leaf's names
   * @throws GeneralSecurityException when a key, a signature or a verification fails
   * @throws IllegalStateException when a structure does not survive its PEM round trip
   */
  public static Result run() throws GeneralSecurityException {
    try {
      Instant now = Instant.now();
      KeyPair anchorKeys = generate("secp384r1");
      // Bouncy Castle encodes the RDNs in the order written, and RFC 2253 prints them reversed:
      // written O first, the JDK reads it back as "CN=…,O=qits".
      X500Name anchorName = new X500Name("O=qits, CN=qits certificates smoke anchor");
      JcaX509ExtensionUtils extensions = new JcaX509ExtensionUtils();
      X509CertificateHolder anchorHolder =
          new JcaX509v3CertificateBuilder(
                  anchorName,
                  serial(),
                  Date.from(now.minus(Duration.ofMinutes(5))),
                  Date.from(now.plus(Duration.ofDays(1))),
                  anchorName,
                  anchorKeys.getPublic())
              .addExtension(Extension.basicConstraints, true, new BasicConstraints(0))
              .addExtension(
                  Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign))
              .addExtension(
                  Extension.subjectKeyIdentifier,
                  false,
                  extensions.createSubjectKeyIdentifier(anchorKeys.getPublic()))
              .build(signer(anchorKeys));
      X509Certificate anchor = parseCertificate(pem(anchorHolder));
      anchor.verify(anchorKeys.getPublic());
      if (anchor.getBasicConstraints() != 0) {
        throw new IllegalStateException("the anchor lost its CA constraint in the PEM round trip");
      }

      KeyPair leafKeys = generate("secp256r1");
      ExtensionsGenerator requested = new ExtensionsGenerator();
      requested.addExtension(
          Extension.subjectAlternativeName,
          false,
          new GeneralNames(new GeneralName(GeneralName.dNSName, LEAF_NAME)));
      PKCS10CertificationRequest csrHolder =
          new JcaPKCS10CertificationRequestBuilder(
                  new X500Name("CN=ignored by the policy"), leafKeys.getPublic())
              .addAttribute(
                  PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, requested.generate())
              .build(
                  new JcaContentSignerBuilder("SHA256withECDSA").build(leafKeys.getPrivate()));
      JcaPKCS10CertificationRequest csr = new JcaPKCS10CertificationRequest(parseCsr(pem(csrHolder)));
      if (!csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(csr.getPublicKey()))) {
        throw new IllegalStateException("the CSR's signature does not verify");
      }
      Extensions asked = csr.getRequestedExtensions();
      GeneralNames names = GeneralNames.fromExtensions(asked, Extension.subjectAlternativeName);
      String first = names.getNames()[0].getName().toString();

      X509CertificateHolder leafHolder =
          new JcaX509v3CertificateBuilder(
                  anchor,
                  serial(),
                  Date.from(now.minus(Duration.ofMinutes(5))),
                  Date.from(now.plus(Duration.ofDays(1))),
                  new X500Name("CN=" + first),
                  csr.getPublicKey())
              .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
              .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature))
              .addExtension(
                  Extension.extendedKeyUsage,
                  false,
                  new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth))
              .addExtension(Extension.subjectAlternativeName, false, names)
              .addExtension(
                  Extension.authorityKeyIdentifier,
                  false,
                  extensions.createAuthorityKeyIdentifier(anchor))
              .build(signer(anchorKeys));
      X509Certificate leaf = parseCertificate(pem(leafHolder));
      leaf.verify(anchor.getPublicKey());
      List<String> leafNames =
          leaf.getSubjectAlternativeNames().stream().map(name -> name.get(1).toString()).toList();
      return new Result(
          anchor.getSubjectX500Principal().getName(),
          leaf.getSubjectX500Principal().getName(),
          leafNames);
    } catch (OperatorCreationException | PKCSException | IOException e) {
      throw new GeneralSecurityException(e.getClass().getSimpleName() + ": " + e.getMessage(), e);
    }
  }

  private static KeyPair generate(String curve) throws GeneralSecurityException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec(curve), RANDOM);
    return generator.generateKeyPair();
  }

  private static ContentSigner signer(KeyPair anchorKeys) throws OperatorCreationException {
    return new JcaContentSignerBuilder("SHA384withECDSA").build(anchorKeys.getPrivate());
  }

  /** 128 random bits, positive. */
  private static BigInteger serial() {
    return new BigInteger(128, RANDOM).setBit(127);
  }

  private static String pem(Object structure) throws IOException {
    StringWriter out = new StringWriter();
    try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
      writer.writeObject(structure);
    }
    return out.toString();
  }

  private static X509Certificate parseCertificate(String pem)
      throws IOException, GeneralSecurityException {
    Object parsed = parse(pem);
    if (!(parsed instanceof X509CertificateHolder holder)) {
      throw new IllegalStateException("not a certificate PEM: " + describe(parsed));
    }
    return new JcaX509CertificateConverter().getCertificate(holder);
  }

  private static PKCS10CertificationRequest parseCsr(String pem) throws IOException {
    Object parsed = parse(pem);
    if (!(parsed instanceof PKCS10CertificationRequest csr)) {
      throw new IllegalStateException("not a certificate request PEM: " + describe(parsed));
    }
    return csr;
  }

  private static Object parse(String pem) throws IOException {
    try (PEMParser parser = new PEMParser(new StringReader(pem))) {
      return parser.readObject();
    }
  }

  private static String describe(Object parsed) {
    return parsed == null ? "nothing" : parsed.getClass().getSimpleName();
  }
}
