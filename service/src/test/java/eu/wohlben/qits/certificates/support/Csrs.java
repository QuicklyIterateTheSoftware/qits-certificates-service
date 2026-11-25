package eu.wohlben.qits.certificates.support;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/**
 * The suite's CSRs: the two fixed fixtures the golden masters send (made once with openssl over one
 * P-256 key that was not kept), and fresh ones made with the JDK's keys.
 *
 * <ul>
 *   <li>{@value #TWO_NAMES}: {@code api.example.org}, {@code www.example.org}.
 *   <li>{@value #INTERNAL_NAME}: {@code db.internal}, which the name rules refuse.
 * </ul>
 */
public final class Csrs {

  public static final String TWO_NAMES = "fixtures/csr/two-names.csr.pem";

  public static final String INTERNAL_NAME = "fixtures/csr/internal-name.csr.pem";

  private Csrs() {}

  /** A fixture CSR's PEM. */
  public static String fixture(String resource) {
    try (var in = Csrs.class.getClassLoader().getResourceAsStream(resource)) {
      if (in == null) {
        throw new IllegalStateException("no fixture " + resource);
      }
      return new String(in.readAllBytes(), StandardCharsets.US_ASCII);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /** {@code {"csr":"<pem>"}}. */
  public static String body(String pem) {
    return "{\"csr\":\"" + pem.replace("\n", "\\n") + "\"}";
  }

  public static KeyPair keys(String algorithm, Object parameter) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
    if (parameter instanceof Integer bits) {
      generator.initialize(bits, new SecureRandom());
    } else {
      generator.initialize(new ECGenParameterSpec((String) parameter), new SecureRandom());
    }
    return generator.generateKeyPair();
  }

  /** A fresh P-256 CSR asking for these dNSNames. */
  public static String forNames(String... names) throws Exception {
    return forNames(keys("EC", "secp256r1"), names);
  }

  /** A CSR over {@code keys} asking for these dNSNames. */
  public static String forNames(KeyPair keys, String... names) throws Exception {
    JcaPKCS10CertificationRequestBuilder builder =
        new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=ignored"), keys.getPublic());
    GeneralName[] sans = new GeneralName[names.length];
    for (int i = 0; i < names.length; i++) {
      sans[i] = new GeneralName(GeneralName.dNSName, names[i]);
    }
    ExtensionsGenerator extensions = new ExtensionsGenerator();
    extensions.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sans));
    builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());
    String algorithm = keys.getPublic().getAlgorithm().equals("RSA") ? "SHA256withRSA" : "SHA256withECDSA";
    StringWriter out = new StringWriter();
    try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
      writer.writeObject(builder.build(new JcaContentSignerBuilder(algorithm).build(keys.getPrivate())));
    }
    return out.toString().replace("\r\n", "\n");
  }
}
