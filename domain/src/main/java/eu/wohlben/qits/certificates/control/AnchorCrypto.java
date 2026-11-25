package eu.wohlben.qits.certificates.control;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Makes an anchor's key and self-signed certificate, and reads both back.
 *
 * <p>Keys and signatures are the JDK's default provider (SunEC); Bouncy Castle only builds the
 * certificate and reads and writes its PEM. The private key is written and read as PKCS#8 by the
 * JDK alone. <b>Nothing here holds a {@link SecureRandom} in a field</b>: a native image refuses
 * one in its image heap (seeded at build time), so every call makes its own.
 */
public final class AnchorCrypto {

  static final String CURVE = "secp384r1";

  static final String SIGNATURE = "SHA384withECDSA";

  /** The PKCS#8 PEM label. Written to {@code key.pem} and nowhere else. */
  private static final String KEY_LABEL = "PRIVATE KEY";

  private static final DateTimeFormatter MONTH =
      DateTimeFormatter.ofPattern("yyyy-MM").withZone(ZoneOffset.UTC);

  /** How far a new certificate's {@code notBefore} is set back, for callers whose clock lags. */
  static final Duration BACKDATE = Duration.ofMinutes(5);

  /** A new anchor: its key pair and its self-signed certificate. */
  public record Made(KeyPair keys, X509Certificate certificate) {}

  private AnchorCrypto() {}

  /**
   * The subject of an anchor made at {@code at}: printed by the JDK as {@code CN=qits platform CA
   * <environment> <yyyy-MM>, O=qits}. Bouncy Castle encodes the RDNs in the order they are added and
   * the JDK prints them reversed, so O goes in first (the conventional order, most significant
   * first, which openssl prints as written).
   */
  static X500Name subject(String environment, Instant at) {
    return new X500NameBuilder(BCStyle.INSTANCE)
        .addRDN(BCStyle.O, "qits")
        .addRDN(BCStyle.CN, "qits platform CA " + environment + " " + MONTH.format(at))
        .build();
  }

  /**
   * Makes an EC P-384 key pair and its self-signed CA certificate: valid from {@code now} (less
   * {@link #BACKDATE}) for {@code validity}, a 128-bit random serial, basicConstraints critical
   * CA:true pathLen 0, keyUsage critical keyCertSign + cRLSign, and a SubjectKeyIdentifier.
   */
  public static Made make(String environment, Instant now, Duration validity)
      throws GeneralSecurityException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec(CURVE), new SecureRandom());
    KeyPair keys = generator.generateKeyPair();
    X500Name name = subject(environment, now);
    try {
      X509CertificateHolder holder =
          new JcaX509v3CertificateBuilder(
                  name,
                  serial(),
                  Date.from(now.minus(BACKDATE)),
                  Date.from(now.plus(validity)),
                  name,
                  keys.getPublic())
              .addExtension(Extension.basicConstraints, true, new BasicConstraints(0))
              .addExtension(
                  Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign))
              .addExtension(
                  Extension.subjectKeyIdentifier,
                  false,
                  new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keys.getPublic()))
              .build(new JcaContentSignerBuilder(SIGNATURE).build(keys.getPrivate()));
      X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(holder);
      certificate.verify(keys.getPublic());
      return new Made(keys, certificate);
    } catch (OperatorCreationException | IOException e) {
      throw new GeneralSecurityException(
          "the anchor certificate could not be built: " + e.getClass().getSimpleName(), e);
    }
  }

  /** 128 random bits, the top one set so the serial is always 16 bytes long. */
  private static BigInteger serial() {
    return new BigInteger(128, new SecureRandom()).setBit(127);
  }

  /** The certificate as one {@code CERTIFICATE} PEM block, ending in a newline. */
  public static String certificatePem(X509Certificate certificate) throws IOException {
    StringWriter out = new StringWriter();
    try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
      writer.writeObject(certificate);
    }
    return out.toString().replace("\r\n", "\n");
  }

  /**
   * Parses one {@code CERTIFICATE} PEM block.
   *
   * @throws GeneralSecurityException when the text is not exactly that (its content is never
   *     quoted)
   */
  public static X509Certificate parseCertificate(String pem) throws GeneralSecurityException {
    Object parsed;
    try (PEMParser parser = new PEMParser(new StringReader(pem))) {
      parsed = parser.readObject();
    } catch (IOException | RuntimeException e) {
      throw new GeneralSecurityException("not a certificate PEM");
    }
    if (!(parsed instanceof X509CertificateHolder holder)) {
      throw new GeneralSecurityException("not a certificate PEM");
    }
    return new JcaX509CertificateConverter().getCertificate(holder);
  }

  /** The private key as PKCS#8 PEM, for {@code key.pem} only. */
  static byte[] keyPem(PrivateKey key) {
    String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
        .encodeToString(key.getEncoded());
    return ("-----BEGIN " + KEY_LABEL + "-----\n" + body + "\n-----END " + KEY_LABEL + "-----\n")
        .getBytes(StandardCharsets.US_ASCII);
  }

  /**
   * Reads a PKCS#8 EC private key from {@code key.pem}'s bytes.
   *
   * @throws GeneralSecurityException when it is not one (the content is never quoted)
   */
  static PrivateKey parseKey(byte[] pem) throws GeneralSecurityException {
    String text = new String(pem, StandardCharsets.US_ASCII).trim();
    String begin = "-----BEGIN " + KEY_LABEL + "-----";
    String end = "-----END " + KEY_LABEL + "-----";
    if (!text.startsWith(begin) || !text.endsWith(end)) {
      throw new GeneralSecurityException("key.pem is not a PKCS#8 PEM");
    }
    byte[] der;
    try {
      der = Base64.getMimeDecoder().decode(text.substring(begin.length(), text.length() - end.length()));
    } catch (IllegalArgumentException e) {
      throw new GeneralSecurityException("key.pem is not base64");
    }
    try {
      return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
    } catch (GeneralSecurityException e) {
      throw new GeneralSecurityException("key.pem is not an EC private key");
    }
  }

  /** Whether {@code key} is the private half of {@code certificate}'s public key. */
  static boolean matches(PrivateKey key, PublicKey publicKey) {
    try {
      byte[] probe = "qits-certificates key check".getBytes(StandardCharsets.US_ASCII);
      Signature signer = Signature.getInstance(SIGNATURE);
      signer.initSign(key);
      signer.update(probe);
      byte[] signature = signer.sign();
      Signature verifier = Signature.getInstance(SIGNATURE);
      verifier.initVerify(publicKey);
      verifier.update(probe);
      return verifier.verify(signature);
    } catch (GeneralSecurityException | RuntimeException e) {
      return false;
    }
  }

  /** The lower-case hex SHA-256 of the certificate's DER encoding. */
  public static String sha256(X509Certificate certificate) throws GeneralSecurityException {
    return sha256(certificate.getEncoded());
  }

  /** The lower-case hex SHA-256 of {@code bytes}. */
  public static String sha256(byte[] bytes) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("no SHA-256", e);
    }
  }
}
