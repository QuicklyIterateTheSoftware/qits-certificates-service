package eu.wohlben.qits.certificates.control;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Builds and signs a leaf. Bouncy Castle assembles the certificate; the signature is the JDK's
 * (SunEC), {@code SHA384withECDSA} by the ACTIVE anchor's key, with the caller's {@link
 * SecureRandom} for both the serial and the signature's nonce. Nothing here keeps one.
 */
final class LeafCrypto {

  private LeafCrypto() {}

  /**
   * The leaf: subject {@code CN=<first name>}, SAN the names, basicConstraints critical CA:false,
   * keyUsage critical digitalSignature (+ keyEncipherment for RSA), extendedKeyUsage serverAuth,
   * the anchor's key id as AuthorityKeyIdentifier, a SubjectKeyIdentifier, and a 128-bit serial.
   * It is verified against the anchor before it is returned.
   */
  static X509Certificate sign(
      Anchor anchor,
      PrivateKey anchorKey,
      LeafPolicy.Request request,
      Instant notBefore,
      Instant notAfter,
      SecureRandom random)
      throws GeneralSecurityException {
    X509Certificate issuer = anchor.certificate();
    X500Name subject =
        new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, request.names().get(0)).build();
    GeneralName[] names =
        request.names().stream()
            .map(n -> new GeneralName(GeneralName.dNSName, n))
            .toArray(GeneralName[]::new);
    int usage = KeyUsage.digitalSignature | (request.rsa() ? KeyUsage.keyEncipherment : 0);
    try {
      JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
      X509CertificateHolder holder =
          new X509v3CertificateBuilder(
                  X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded()),
                  new BigInteger(128, random).setBit(127),
                  Date.from(notBefore),
                  Date.from(notAfter),
                  subject,
                  request.key())
              .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
              .addExtension(Extension.keyUsage, true, new KeyUsage(usage))
              .addExtension(
                  Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth))
              .addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names))
              .addExtension(Extension.authorityKeyIdentifier, false, authorityKeyId(issuer, utils))
              .addExtension(
                  Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(request.key()))
              .build(
                  new JcaContentSignerBuilder(AnchorCrypto.SIGNATURE)
                      .setSecureRandom(random)
                      .build(anchorKey));
      X509Certificate leaf = new JcaX509CertificateConverter().getCertificate(holder);
      leaf.verify(issuer.getPublicKey());
      return leaf;
    } catch (OperatorCreationException | IOException e) {
      throw new GeneralSecurityException(
          "the leaf could not be built: " + e.getClass().getSimpleName(), e);
    }
  }

  /** The anchor's own SubjectKeyIdentifier as a key id; computed from its key when it has none. */
  private static AuthorityKeyIdentifier authorityKeyId(X509Certificate issuer, JcaX509ExtensionUtils utils)
      throws GeneralSecurityException {
    byte[] ski = issuer.getExtensionValue(Extension.subjectKeyIdentifier.getId());
    if (ski == null) {
      return utils.createAuthorityKeyIdentifier(issuer.getPublicKey());
    }
    byte[] id =
        SubjectKeyIdentifier.getInstance(ASN1OctetString.getInstance(ski).getOctets()).getKeyIdentifier();
    return new AuthorityKeyIdentifier(id);
  }
}
