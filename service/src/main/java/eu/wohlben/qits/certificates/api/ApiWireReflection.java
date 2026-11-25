package eu.wohlben.qits.certificates.api;

import io.quarkus.runtime.annotations.RegisterForReflection;

/**
 * Native-image reflection registration for every type Jackson touches on this API. Each of them
 * rides in {@code Response.entity(...)}, which hides the type from the build-time analysis: in the
 * native binary that is a 500 behind a green JVM suite.
 *
 * <p><b>A new served type joins this list in the commit that adds it</b>; ApiWireReflectionTest
 * fails naming any nested type of {@link AnchorsWire} or {@link LeavesWire} left out.
 */
@RegisterForReflection(
    targets = {
      AnchorsWire.AnchorDto.class,
      AnchorsWire.AnchorsDto.class,
      AnchorsWire.ErrorBody.class,
      LeavesWire.LeafRequest.class,
      LeavesWire.LeafDto.class,
      LeavesWire.NameRefused.class
    })
public final class ApiWireReflection {

  private ApiWireReflection() {}
}
