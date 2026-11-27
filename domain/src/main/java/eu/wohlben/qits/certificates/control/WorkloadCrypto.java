package eu.wohlben.qits.certificates.control;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Builds and signs a workload certificate, like {@link LeafCrypto} builds a leaf: Bouncy Castle
 * assembles it, SunEC signs it ({@code SHA384withECDSA}, the ACTIVE anchor's key), and the caller's
 * {@link SecureRandom} gives the serial and the nonce. Nothing here keeps one.
 */
final class WorkloadCrypto {

  /** The longest CN X.520 allows (ub-common-name). The CN is informational, so it is cut. */
  static final int MAX_CN = 64;

  private WorkloadCrypto() {}

  /**
   * The certificate: subject {@code CN=<principal>} (cut at {@value #MAX_CN}); SAN the request's
   * URIs, then its DNS names; basicConstraints critical CA:false; keyUsage critical
   * digitalSignature (+ keyEncipherment for RSA); extendedKeyUsage clientAuth, + serverAuth when it
   * has a DNS name; the anchor's key id; a SubjectKeyIdentifier; a 128-bit serial. It is verified
   * against the anchor before it is returned.
   */
  static X509Certificate sign(
      Anchor anchor,
      PrivateKey anchorKey,
      WorkloadRequest request,
      SubjectPublicKeyInfo key,
      boolean rsa,
      Instant notBefore,
      Instant notAfter,
      SecureRandom random)
      throws GeneralSecurityException {
    X509Certificate issuer = anchor.certificate();
    String cn = request.principal();
    X500Name subject =
        new X500NameBuilder(BCStyle.INSTANCE)
            .addRDN(BCStyle.CN, cn.length() > MAX_CN ? cn.substring(0, MAX_CN) : cn)
            .build();
    List<GeneralName> names = new ArrayList<>();
    request.uris().forEach(uri -> names.add(new GeneralName(GeneralName.uniformResourceIdentifier, uri)));
    request.dnsNames().forEach(dns -> names.add(new GeneralName(GeneralName.dNSName, dns)));
    KeyPurposeId[] purposes =
        request.serverAuth()
            ? new KeyPurposeId[] {KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth}
            : new KeyPurposeId[] {KeyPurposeId.id_kp_clientAuth};
    int usage = KeyUsage.digitalSignature | (rsa ? KeyUsage.keyEncipherment : 0);
    try {
      JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
      X509CertificateHolder holder =
          new X509v3CertificateBuilder(
                  X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded()),
                  new BigInteger(128, random).setBit(127),
                  Date.from(notBefore),
                  Date.from(notAfter),
                  subject,
                  key)
              .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
              .addExtension(Extension.keyUsage, true, new KeyUsage(usage))
              .addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purposes))
              .addExtension(
                  Extension.subjectAlternativeName,
                  false,
                  new GeneralNames(names.toArray(GeneralName[]::new)))
              .addExtension(
                  Extension.authorityKeyIdentifier, false, LeafCrypto.authorityKeyId(issuer, utils))
              .addExtension(
                  Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(key))
              .build(
                  new JcaContentSignerBuilder(AnchorCrypto.SIGNATURE)
                      .setSecureRandom(random)
                      .build(anchorKey));
      X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(holder);
      certificate.verify(issuer.getPublicKey());
      return certificate;
    } catch (OperatorCreationException | IOException e) {
      throw new GeneralSecurityException(
          "the workload certificate could not be built: " + e.getClass().getSimpleName(), e);
    }
  }
}
