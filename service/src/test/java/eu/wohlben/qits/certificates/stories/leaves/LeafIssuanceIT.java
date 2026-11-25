package eu.wohlben.qits.certificates.stories.leaves;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;

import eu.wohlben.qits.certificates.stories.bootstrap.CertificatesBootstrapIT;
import eu.wohlben.qits.servicemock.idp.MockIdp;
import eu.wohlben.qits.userflows.Interactions;
import eu.wohlben.qits.userflows.NetworkCapture;
import eu.wohlben.qits.userflows.NetworkTaps;
import eu.wohlben.qits.userflows.UserStory;
import eu.wohlben.qits.userflows.UserStoryDescription;
import eu.wohlben.qits.userflows.report.ReportAssertions;
import eu.wohlben.qits.userflows.report.UserflowReport;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.response.Response;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

/**
 * The leaf door against the <b>packaged</b> service, with the OIDC tenant on: the native IT's
 * second half (qits-2648). The process parses a CSR, checks its signature through the JDK, reads
 * the ACTIVE anchor's key from the volume and signs the leaf with it, Bouncy Castle building the
 * certificate. Under {@code ./mvnw verify -Dnative} that is the binary doing it end to end, which a
 * green JVM suite cannot show.
 */
@QuarkusIntegrationTest
@TestProfile(CertificatesBootstrapIT.PackagedWithMockIdp.class)
public class LeafIssuanceIT {

  static final String CATEGORY = "leaves";

  static final String SLUG = "a-platform-service-gets-a-leaf-certificate-for-its-names";

  static final String SERVICE = "qits-certificates";

  static final String LEAVES = "/certificates/api/leaves";

  @BeforeAll
  static void tapTheNetwork() {
    NetworkTaps.restAssured(SERVICE, path -> false);
  }

  static String bearer(String subject, String role) {
    return "Bearer "
        + MockIdp.attach().token().subject(subject).audience("qits-platform").groups(role).mint();
  }

  static String csr(String... names) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
    KeyPair keys = generator.generateKeyPair();
    GeneralName[] sans = new GeneralName[names.length];
    for (int i = 0; i < names.length; i++) {
      sans[i] = new GeneralName(GeneralName.dNSName, names[i]);
    }
    ExtensionsGenerator extensions = new ExtensionsGenerator();
    extensions.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sans));
    JcaPKCS10CertificationRequestBuilder builder =
        new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=ignored"), keys.getPublic());
    builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());
    StringWriter out = new StringWriter();
    try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
      writer.writeObject(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate())));
    }
    return "{\"csr\":\"" + out.toString().replace("\r\n", "\n").replace("\n", "\\n") + "\"}";
  }

  static List<X509Certificate> certificates(String pem) throws Exception {
    return CertificateFactory.getInstance("X.509")
        .generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)))
        .stream()
        .map(X509Certificate.class::cast)
        .toList();
  }

  @UserStory(value = "A platform service gets a leaf certificate for its names", category = CATEGORY)
  @UserStoryDescription(
      """
      A platform service that serves TLS of its own (qits-egress first) asks qits-certificates for a
      leaf: it holds qits:system, its token's sub is on the requester list, and it sends a PKCS#10
      CSR for its names. The ACTIVE trust anchor signs a short-lived serverAuth leaf for exactly
      those names, and every container that trusts the anchors trusts it. A service that is not on
      the list, or a name the rules keep out of reach, is refused, and every decision is one audit
      line.
      """)
  void aPlatformServiceGetsALeaf(Interactions story) throws Exception {
    story.note("qits-certificates is up with its ACTIVE anchor; qits-egress holds a qits:system token");
    NetworkCapture.actor("qits-egress");
    Response issued =
        given()
            .header("Authorization", bearer(CertificatesBootstrapIT.LEAF_REQUESTER, "qits:system"))
            .contentType("application/json")
            .body(csr("api.example.org", "www.example.org"))
            .post(LEAVES);
    issued.then().statusCode(201).body(not(containsString("PRIVATE KEY")));
    List<X509Certificate> chain = certificates(issued.path("chain"));
    assertEquals(2, chain.size(), "the leaf, then the anchor");
    X509Certificate leaf = chain.get(0);
    X509Certificate anchor = chain.get(1);
    leaf.verify(anchor.getPublicKey());
    assertEquals(
        List.of(List.of(2, "api.example.org"), List.of(2, "www.example.org")),
        List.copyOf(leaf.getSubjectAlternativeNames()));
    assertEquals(List.of("1.3.6.1.5.5.7.3.1"), leaf.getExtendedKeyUsage());
    assertEquals(-1, leaf.getBasicConstraints());
    assertEquals(leaf.getSerialNumber().toString(16), issued.path("serial"));
    story.note("the leaf is signed by the ACTIVE anchor, for exactly the names asked").as("issued");

    given()
        .header("Authorization", bearer(CertificatesBootstrapIT.LEAF_REQUESTER, "qits:system"))
        .contentType("application/json")
        .body(csr("db.internal"))
        .post(LEAVES)
        .then()
        .statusCode(400)
        .body("error", equalTo("name refused"))
        .body("name", equalTo("db.internal"));
    story.note("a name under .internal is refused, and named").as("name-refused");

    NetworkCapture.actor("another platform service");
    given()
        .header("Authorization", bearer("dev-qits-ci", "qits:system"))
        .contentType("application/json")
        .body(csr("ci.example.org"))
        .post(LEAVES)
        .then()
        .statusCode(403)
        .body("error", equalTo("not a leaf requester"));
    story.note("a qits:system service that is not on the requester list gets 403").as("not-a-requester");

    NetworkCapture.actor("an agent");
    given()
        .header("Authorization", bearer("tok-project-agent-qits-a", "qits:agent"))
        .contentType("application/json")
        .body(csr("agent.example.org"))
        .post(LEAVES)
        .then()
        .statusCode(403);
    story.note("an agent's token, without qits:system, gets 403 too").as("agent");
  }

  @AfterAll
  static void theStoryReportIsComplete() {
    ReportAssertions.assertComplete(CATEGORY, SLUG, UserflowReport.PASSED);
    ReportAssertions.assertEdge(
        CATEGORY, SLUG, "http", "qits-egress", SERVICE, "POST /certificates/api/leaves -> 201");
    ReportAssertions.assertStepId(CATEGORY, SLUG, "agent");
  }
}
