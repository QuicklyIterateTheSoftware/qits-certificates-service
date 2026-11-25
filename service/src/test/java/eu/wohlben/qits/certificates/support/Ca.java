package eu.wohlben.qits.certificates.support;

import eu.wohlben.qits.certificates.control.Anchors;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.Comparator;
import java.util.stream.Stream;

/**
 * <b>The suite's CA volume</b> ({@code %test.qits.certificates.ca-dir}), staged per test: wiped
 * empty, booted fresh, or loaded with the fixed fixture anchors under {@code
 * src/test/resources/fixtures/anchors/} — two anchors made once by the service's own code and
 * committed, so a recording of them is byte-identical on every run.
 *
 * <ul>
 *   <li>{@value #ACTIVE}: ACTIVE, made 2026-11-01, valid to 2031-11-01.
 *   <li>{@value #PENDING}: PENDING, made 2026-11-20, ACTIVE from 2026-12-20.
 * </ul>
 */
@ApplicationScoped
public class Ca {

  public static final String ACTIVE = "6f1c2a7e-3b4d-4e5f-8a9b-0c1d2e3f4a5b";

  public static final String PENDING = "7a2d3b8f-4c5e-4f60-9bac-1d2e3f4a5b6c";

  /** Where the staged states pin the clock: after both fixtures were made, before activation. */
  public static final Instant STAGED_AT = Instant.parse("2026-11-25T12:00:00Z");

  @Inject Anchors anchors;

  @Inject TestClock clock;

  /** An empty volume, loaded: no anchor at all. */
  public void empty() {
    clock.reset();
    wipe();
    anchors.load();
  }

  /** An empty volume, then the startup run: one fresh ACTIVE anchor, made now. */
  public void boot() {
    clock.reset();
    wipe();
    anchors.start();
  }

  /** The fixture anchors named, alone on the volume, loaded, with the clock pinned. */
  public void stage(String... ids) {
    clock.set(STAGED_AT);
    wipe();
    try {
      Path fixtures = Path.of(Ca.class.getClassLoader().getResource("fixtures/anchors").toURI());
      for (String id : ids) {
        Path target = Files.createDirectories(anchors.directory().resolve(id));
        try (Stream<Path> files = Files.list(fixtures.resolve(id))) {
          for (Path file : files.toList()) {
            Path copy = target.resolve(file.getFileName());
            Files.copy(file, copy, StandardCopyOption.REPLACE_EXISTING);
            Files.setPosixFilePermissions(
                copy,
                PosixFilePermissions.fromString(
                    file.getFileName().toString().equals("key.pem") ? "rw-------" : "rw-r--r--"));
          }
        }
      }
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    } catch (URISyntaxException e) {
      throw new IllegalStateException(e);
    }
    anchors.load();
  }

  /** {@code <ca-dir>/anchors}. */
  public Path directory() {
    return anchors.directory();
  }

  private void wipe() {
    Path dir = anchors.directory();
    if (!Files.exists(dir)) {
      return;
    }
    try (Stream<Path> all = Files.walk(dir)) {
      for (Path path : all.sorted(Comparator.reverseOrder()).toList()) {
        Files.delete(path);
      }
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }
}
