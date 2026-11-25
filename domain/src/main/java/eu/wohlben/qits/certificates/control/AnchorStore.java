package eu.wohlben.qits.certificates.control;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.jboss.logging.Logger;

/**
 * The anchors on the volume: one directory per anchor, {@code <ca-dir>/anchors/<anchorId>/},
 * holding {@code cert.pem} (0644), {@code key.pem} (PKCS#8, 0600) and {@code state.json} (0644).
 *
 * <p><b>Every write is a temp file renamed into place</b>, in the same directory, so a crash leaves
 * the old file or the new one and never half of either. A new anchor is assembled in a hidden
 * staging directory ({@code .new-<id>}) and renamed in whole, so it appears with all three files or
 * not at all.
 *
 * <p><b>A directory it cannot read is logged at ERROR and skipped, never deleted</b>: a malformed
 * {@code state.json}, a certificate that does not parse or whose SHA-256 is not the state's, or a
 * key that is missing or not the certificate's. Hidden entries (a staging directory a crash left
 * behind) are skipped silently. No message ever quotes a file's content.
 */
public final class AnchorStore {

  private static final Logger LOG = Logger.getLogger(AnchorStore.class);

  static final String CERT = "cert.pem";
  static final String KEY = "key.pem";
  static final String STATE = "state.json";

  private static final Set<PosixFilePermission> DIRECTORY = PosixFilePermissions.fromString("rwx------");
  private static final Set<PosixFilePermission> PUBLIC = PosixFilePermissions.fromString("rw-r--r--");
  private static final Set<PosixFilePermission> SECRET = PosixFilePermissions.fromString("rw-------");

  private final Path anchors;

  private final boolean posix;

  public AnchorStore(Path caDir) {
    this.anchors = caDir.resolve("anchors");
    this.posix = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
  }

  /** {@code <ca-dir>/anchors}. */
  public Path directory() {
    return anchors;
  }

  /** Every readable anchor, in directory-name order; an unreadable one is logged and skipped. */
  List<Anchor> load() {
    List<Anchor> loaded = new ArrayList<>();
    if (!Files.isDirectory(anchors)) {
      return loaded;
    }
    Set<Path> entries = new TreeSet<>();
    try (DirectoryStream<Path> dirs = Files.newDirectoryStream(anchors)) {
      dirs.forEach(entries::add);
    } catch (IOException e) {
      throw new AnchorStoreException("the anchors directory " + anchors + " cannot be listed", e);
    }
    for (Path dir : entries) {
      String name = dir.getFileName().toString();
      if (name.startsWith(".")) {
        continue;
      }
      if (!Files.isDirectory(dir)) {
        LOG.errorf("anchor entry %s is not a directory: ignored, and left in place", dir);
        continue;
      }
      try {
        loaded.add(read(dir));
      } catch (Unreadable e) {
        LOG.errorf("anchor directory %s is ignored, and left in place: %s", dir, e.getMessage());
      }
    }
    return loaded;
  }

  /** Why a directory is skipped; the message names the file and the fault, never content. */
  static final class Unreadable extends Exception {
    Unreadable(String message) {
      super(message, null, false, false);
    }
  }

  private Anchor read(Path dir) throws Unreadable {
    AnchorState state;
    try {
      state = AnchorState.parse(Files.readString(dir.resolve(STATE), StandardCharsets.UTF_8));
    } catch (NoSuchFileException e) {
      throw new Unreadable(STATE + " is missing");
    } catch (IOException e) {
      throw new Unreadable(STATE + " cannot be read (" + e.getClass().getSimpleName() + ")");
    } catch (IllegalArgumentException e) {
      throw new Unreadable(e.getMessage());
    }
    if (!state.id().equals(dir.getFileName().toString())) {
      throw new Unreadable("state.json names the anchor " + state.id() + ", not its directory");
    }
    String pem;
    X509Certificate certificate;
    try {
      pem = Files.readString(dir.resolve(CERT), StandardCharsets.US_ASCII);
      certificate = AnchorCrypto.parseCertificate(pem);
      if (!AnchorCrypto.sha256(certificate).equals(state.sha256())) {
        throw new Unreadable(CERT + "'s SHA-256 is not the one state.json records");
      }
    } catch (NoSuchFileException e) {
      throw new Unreadable(CERT + " is missing");
    } catch (IOException | GeneralSecurityException | RuntimeException e) {
      throw new Unreadable(CERT + " is not a certificate");
    }
    if (state.status() != AnchorStatus.RETIRED) {
      PrivateKey key;
      try {
        key = AnchorCrypto.parseKey(Files.readAllBytes(dir.resolve(KEY)));
      } catch (NoSuchFileException e) {
        throw new Unreadable(KEY + " is missing for a " + state.status() + " anchor");
      } catch (IOException | GeneralSecurityException e) {
        throw new Unreadable(KEY + " is not a PKCS#8 EC key");
      }
      if (!AnchorCrypto.matches(key, certificate.getPublicKey())) {
        throw new Unreadable(KEY + " is not the key of " + CERT);
      }
    }
    return new Anchor(state, certificate, pem, dir);
  }

  /**
   * Writes a new anchor: staged under {@code .new-<id>}, then renamed to {@code <id>} in one step.
   */
  Anchor create(AnchorState state, AnchorCrypto.Made made) {
    Path target = anchors.resolve(state.id());
    Path staging = anchors.resolve(".new-" + state.id());
    try {
      ensureDirectory(anchors);
      Files.createDirectory(staging);
      restrict(staging, DIRECTORY);
      String pem = AnchorCrypto.certificatePem(made.certificate());
      write(staging.resolve(CERT), pem.getBytes(StandardCharsets.US_ASCII), PUBLIC);
      write(staging.resolve(KEY), AnchorCrypto.keyPem(made.keys().getPrivate()), SECRET);
      write(staging.resolve(STATE), state.toJson().getBytes(StandardCharsets.UTF_8), PUBLIC);
      Files.move(staging, target, StandardCopyOption.ATOMIC_MOVE);
      return new Anchor(state, made.certificate(), pem, target);
    } catch (IOException e) {
      throw new AnchorStoreException("the anchor " + state.id() + " could not be written", e);
    }
  }

  /** Replaces the anchor's {@code state.json}. */
  Anchor update(Anchor anchor, AnchorState next) {
    try {
      write(anchor.directory().resolve(STATE), next.toJson().getBytes(StandardCharsets.UTF_8), PUBLIC);
      return anchor.with(next);
    } catch (IOException e) {
      throw new AnchorStoreException("the state of anchor " + anchor.id() + " could not be written", e);
    }
  }

  /** Deletes the anchor's {@code key.pem}; nothing when it is already gone. */
  void deleteKey(Anchor anchor) {
    try {
      Files.deleteIfExists(anchor.directory().resolve(KEY));
    } catch (IOException e) {
      throw new AnchorStoreException("the key of anchor " + anchor.id() + " could not be deleted", e);
    }
  }

  boolean hasKey(Anchor anchor) {
    return Files.exists(anchor.directory().resolve(KEY));
  }

  /** The anchor's private key, read from {@code key.pem} and checked against its certificate. */
  PrivateKey readKey(Anchor anchor) {
    try {
      PrivateKey key = AnchorCrypto.parseKey(Files.readAllBytes(anchor.directory().resolve(KEY)));
      if (!AnchorCrypto.matches(key, anchor.certificate().getPublicKey())) {
        throw new AnchorStoreException("the key of anchor " + anchor.id() + " is not its certificate's");
      }
      return key;
    } catch (IOException | GeneralSecurityException e) {
      throw new AnchorStoreException(
          "the key of anchor " + anchor.id() + " cannot be read (" + e.getClass().getSimpleName() + ")");
    }
  }

  private void ensureDirectory(Path dir) throws IOException {
    if (!Files.isDirectory(dir)) {
      Files.createDirectories(dir);
      restrict(dir, DIRECTORY);
    }
  }

  /** Writes {@code content} to a temp file beside {@code target}, flushed, then renames it over. */
  private void write(Path target, byte[] content, Set<PosixFilePermission> mode) throws IOException {
    Path temp = target.resolveSibling("." + target.getFileName() + ".tmp");
    Files.deleteIfExists(temp);
    try {
      if (posix) {
        Files.createFile(temp, PosixFilePermissions.asFileAttribute(SECRET));
      } else {
        Files.createFile(temp);
      }
      try (FileChannel channel = FileChannel.open(temp, StandardOpenOption.WRITE)) {
        ByteBuffer buffer = ByteBuffer.wrap(content);
        while (buffer.hasRemaining()) {
          channel.write(buffer);
        }
        channel.force(true);
      }
      restrict(temp, mode);
      Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } finally {
      Files.deleteIfExists(temp);
    }
  }

  private void restrict(Path path, Set<PosixFilePermission> mode) throws IOException {
    if (posix) {
      Files.setPosixFilePermissions(path, mode);
    }
  }
}
