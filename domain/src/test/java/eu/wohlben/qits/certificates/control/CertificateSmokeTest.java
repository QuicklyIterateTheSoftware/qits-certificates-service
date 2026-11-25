package eu.wohlben.qits.certificates.control;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.Security;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The smoke on the JVM. The same path runs in the packaged artifact through the readiness check
 * {@code certificates-crypto}, which {@code CertificatesBootstrapIT} asserts — natively under
 * {@code ./mvnw verify -Dnative}.
 */
class CertificateSmokeTest {

  @Test
  void anAnchorIsSelfSignedAndALeafIsIssuedFromACsr() throws Exception {
    CertificateSmoke.Result result = CertificateSmoke.run();

    assertEquals("CN=qits certificates smoke anchor,O=qits", result.anchorSubject());
    assertEquals("CN=" + CertificateSmoke.LEAF_NAME, result.leafSubject());
    assertEquals(List.of(CertificateSmoke.LEAF_NAME), result.leafNames());
  }

  @Test
  void bouncyCastleIsNotARegisteredProvider() {
    // The design's rule: the JDK's SunEC signs; Bouncy Castle builds and parses structures only.
    assertEquals(
        List.of(),
        Arrays.stream(Security.getProviders())
            .map(provider -> provider.getName())
            .filter("BC"::equals)
            .toList());
  }
}
