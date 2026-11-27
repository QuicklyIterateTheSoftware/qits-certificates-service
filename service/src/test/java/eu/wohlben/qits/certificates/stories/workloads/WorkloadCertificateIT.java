package eu.wohlben.qits.certificates.stories.workloads;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;

import eu.wohlben.qits.auth.WorkloadPrincipal;
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
import java.util.Map;
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
 * The workload certificate door against the <b>packaged</b> service, with the OIDC tenant on
 * (qits-2756). The process validates a real token, maps its claims through qits-auth-core's
 * {@link WorkloadPrincipal}, takes only the key from the CSR and signs a client certificate with
 * the ACTIVE anchor. Under {@code ./mvnw verify -Dnative} that is the binary doing it end to end.
 */
@QuarkusIntegrationTest
@TestProfile(CertificatesBootstrapIT.PackagedWithMockIdp.class)
public class WorkloadCertificateIT {

  static final String CATEGORY = "workloads";

  static final String SLUG = "a-workload-gets-a-client-certificate-for-its-own-principal";

  static final String SERVICE = "qits-certificates";

  static final String DOOR = "/certificates/api/workload-certificates";

  static final String AGENT = "6fe232fc-0000-4000-8000-000000000001";

  static final String PROJECT = "8273c743-e0bb-4d93-90d4-391aa10d9151";

  @BeforeAll
  static void tapTheNetwork() {
    NetworkTaps.restAssured(SERVICE, path -> false);
  }

  static String bearer(String subject, Map<String, Object> claims, String... groups) {
    MockIdp.TokenBuilder token =
        MockIdp.attach().token().subject(subject).audience("qits-platform").groups(groups);
    claims.forEach(token::claim);
    return "Bearer " + token.mint();
  }

  /** A CSR whose subject and names are a workload's attempt to name someone else. */
  static String csr(String... names) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
    KeyPair keys = generator.generateKeyPair();
    GeneralName[] sans = new GeneralName[names.length];
    for (int i = 0; i < names.length; i++) {
      sans[i] = new GeneralName(GeneralName.uniformResourceIdentifier, names[i]);
    }
    JcaPKCS10CertificationRequestBuilder builder =
        new JcaPKCS10CertificationRequestBuilder(
            new X500Name("CN=application:qits-idp"), keys.getPublic());
    if (sans.length > 0) {
      ExtensionsGenerator extensions = new ExtensionsGenerator();
      extensions.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sans));
      builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate());
    }
    StringWriter out = new StringWriter();
    try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
      writer.writeObject(
          builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate())));
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

  @UserStory(
      value = "A workload gets a client certificate for its own principal",
      category = CATEGORY)
  @UserStoryDescription(
      """
      A workload makes its key, sends only a CSR, and proves who it is with its qits bearer. The
      ACTIVE trust anchor signs a client certificate that lives one day and names the principal
      the bearer maps to: an application, with its wire alias for TLS of its own, or an agent and
      its project. Whatever the CSR names is ignored, and a person's or an exchanged token gets no
      workload certificate.
      """)
  void aWorkloadGetsItsCertificate(Interactions story) throws Exception {
    story.note("qits-certificates is up with its ACTIVE anchor; qits-edge holds its service token");
    NetworkCapture.actor("qits-edge");
    Response issued =
        given()
            .header(
                "Authorization",
                bearer(
                    "dev-qits-edge",
                    Map.of("project", "*"),
                    "qits:system",
                    "clients/dev-qits-edge"))
            .contentType("application/json")
            .body(csr("urn:qits:principal:application:qits-idp"))
            .post(DOOR);
    issued
        .then()
        .statusCode(201)
        .body(not(containsString("PRIVATE KEY")))
        .body("principal", equalTo("application:qits-edge"));
    List<X509Certificate> chain = certificates(issued.path("chain"));
    assertEquals(2, chain.size(), "the certificate, then the anchor");
    X509Certificate certificate = chain.get(0);
    certificate.verify(chain.get(1).getPublicKey());
    assertEquals(
        List.of(
            List.of(6, "urn:qits:principal:application:qits-edge"), List.of(2, "dev-qits-edge")),
        List.copyOf(certificate.getSubjectAlternativeNames()),
        "the CSR's qits-idp never reaches it");
    assertEquals(
        List.of("1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1"), certificate.getExtendedKeyUsage());
    assertEquals(
        new WorkloadPrincipal("application", "qits-edge"),
        WorkloadPrincipal.fromCertificate(certificate));
    assertEquals(
        86_400_000L + 300_000L,
        certificate.getNotAfter().getTime() - certificate.getNotBefore().getTime(),
        "one day, from five minutes back");
    story.note("the certificate names qits-edge, from its token, not the CSR").as("application");

    NetworkCapture.actor("a workspace agent");
    Response agent =
        given()
            .header(
                "Authorization",
                bearer(
                    "tok-workspace-agent-x",
                    Map.of("agent", AGENT, "project", PROJECT),
                    "qits:agent"))
            .contentType("application/json")
            .body(csr())
            .post(DOOR);
    agent.then().statusCode(201).body("principal", equalTo("agent:" + AGENT));
    X509Certificate agentCertificate = certificates(agent.path("certificate")).get(0);
    assertEquals(
        List.of(
            List.of(6, "urn:qits:principal:agent:" + AGENT),
            List.of(6, "urn:qits:project:" + PROJECT)),
        List.copyOf(agentCertificate.getSubjectAlternativeNames()));
    assertEquals(List.of("1.3.6.1.5.5.7.3.2"), agentCertificate.getExtendedKeyUsage());
    story.note("an agent's certificate names the agent and its project, clientAuth only").as("agent");

    NetworkCapture.actor("a person");
    given()
        .header(
            "Authorization",
            bearer(
                "6b0c1f4e-0000-4000-8000-00000000000a",
                Map.of("credential_type", "cli"),
                "qits:admin"))
        .contentType("application/json")
        .body(csr())
        .post(DOOR)
        .then()
        .statusCode(403)
        .body("error", equalTo("a person's token"));
    story.note("a person's token gets no workload certificate").as("person");

    NetworkCapture.actor("an exchanged token");
    given()
        .header(
            "Authorization",
            bearer(
                "dev-qits-edge",
                Map.of("act", Map.of("sub", "dev-qits-egress")),
                "qits:system",
                "clients/dev-qits-edge"))
        .contentType("application/json")
        .body(csr())
        .post(DOOR)
        .then()
        .statusCode(403)
        .body("error", equalTo("an exchanged token"));
    story.note("a token that speaks for someone else gets none either").as("exchanged");
  }

  @AfterAll
  static void theStoryReportIsComplete() {
    ReportAssertions.assertComplete(CATEGORY, SLUG, UserflowReport.PASSED);
    ReportAssertions.assertEdge(
        CATEGORY,
        SLUG,
        "http",
        "qits-edge",
        SERVICE,
        "POST /certificates/api/workload-certificates -> 201");
    ReportAssertions.assertStepId(CATEGORY, SLUG, "exchanged");
  }
}
