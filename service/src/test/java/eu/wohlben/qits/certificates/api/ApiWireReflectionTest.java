package eu.wohlben.qits.certificates.api;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.quarkus.runtime.annotations.RegisterForReflection;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * {@link ApiWireReflection} is complete: every nested type of {@link AnchorsWire}, {@link
 * LeavesWire} and {@link WorkloadsWire}. On a JVM
 * everything binds regardless; the failure this guards is a 500 in the native binary, so the only
 * way to catch it early is the commit that forgets the list.
 */
class ApiWireReflectionTest {

  @Test
  void everyWireTypeIsRegistered() {
    RegisterForReflection registration =
        ApiWireReflection.class.getAnnotation(RegisterForReflection.class);
    assertNotNull(registration, "the annotation IS the class");
    Set<Class<?>> registered = Set.of(registration.targets());
    List<Class<?>> nested = new ArrayList<>();
    nested.addAll(List.of(AnchorsWire.class.getDeclaredClasses()));
    nested.addAll(List.of(LeavesWire.class.getDeclaredClasses()));
    nested.addAll(List.of(WorkloadsWire.class.getDeclaredClasses()));
    assertTrue(nested.size() >= 8, "the sweep found only " + nested.size() + " wire types");
    for (Class<?> type : nested) {
      assertTrue(
          registered.contains(type),
          type.getSimpleName() + " is on the wire and not in ApiWireReflection");
    }
  }
}
