package eu.wohlben.qits.certificates.control;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/** CSRs for the tests, made with the JDK's keys and Bouncy Castle's builder. */
final class Csrs {

  private Csrs() {}

  static KeyPair ec(String curve) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec(curve), new SecureRandom());
    return generator.generateKeyPair();
  }

  static KeyPair rsa(int bits) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(bits, new SecureRandom());
    return generator.generateKeyPair();
  }

  /** A P-256 CSR asking for these dNSNames. */
  static String forNames(String... names) throws Exception {
    return pem(request(ec("secp256r1"), dns(names)));
  }

  static GeneralName[] dns(String... names) {
    GeneralName[] out = new GeneralName[names.length];
    for (int i = 0; i < names.length; i++) {
      out[i] = new GeneralName(GeneralName.dNSName, names[i]);
    }
    return out;
  }

  /** A CSR over {@code keys} asking for {@code names}; none at all when {@code names} is null. */
  static PKCS10CertificationRequest request(KeyPair keys, GeneralName... names) throws Exception {
    JcaPKCS10CertificationRequestBuilder builder =
        new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=whatever the caller says"), keys.getPublic());
    if (names != null) {
      ExtensionsGenerator extensions = new ExtensionsGenerator();
      extensions.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
      builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());
    }
    String algorithm = keys.getPublic().getAlgorithm().equals("RSA") ? "SHA256withRSA" : "SHA256withECDSA";
    return builder.build(new JcaContentSignerBuilder(algorithm).build(keys.getPrivate()));
  }

  /** The same request with one bit of its signature flipped. */
  static PKCS10CertificationRequest tampered(PKCS10CertificationRequest csr) {
    CertificationRequest structure = csr.toASN1Structure();
    byte[] signature = structure.getSignature().getBytes();
    signature[signature.length - 1] ^= 1;
    return new PKCS10CertificationRequest(
        new CertificationRequest(
            structure.getCertificationRequestInfo(),
            structure.getSignatureAlgorithm(),
            new DERBitString(signature)));
  }

  static String pem(PKCS10CertificationRequest csr) throws Exception {
    StringWriter out = new StringWriter();
    try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
      writer.writeObject(csr);
    }
    return out.toString();
  }
}
