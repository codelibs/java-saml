package org.codelibs.saml2.core.replay;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Default in-memory, thread-safe {@link ReplayCache} implementation backed by a
 * {@link ConcurrentHashMap}. Expired entries are evicted opportunistically (no
 * background threads are started by this class).
 */
public class InMemoryReplayCache implements ReplayCache {

    /** IDs longer than this are kept as their SHA-256 digest, so an entry never costs more than a digest. */
    private static final int MAX_KEY_LENGTH = 128;

    /** Number of registrations between opportunistic sweeps of expired entries. */
    private static final long SWEEP_INTERVAL = 1000L;

    /** Map of id to the instant after which the entry may be evicted. */
    private final ConcurrentHashMap<String, Instant> entries = new ConcurrentHashMap<>();

    /** Counts registrations to decide when to opportunistically sweep expired entries. */
    private final AtomicLong registrationCount = new AtomicLong();

    /**
     * Constructs a new, empty {@code InMemoryReplayCache}.
     */
    public InMemoryReplayCache() {
        // No-op: entries map starts empty.
    }

    /** {@inheritDoc} */
    @Override
    public boolean registerAndCheck(final String id, final Instant expiresAt) {
        final Instant now = Instant.now();
        final AtomicBoolean replay = new AtomicBoolean(false);
        final String entryKey = toKey(id);

        entries.compute(entryKey, (key, previousExpiresAt) -> {
            if (previousExpiresAt != null && previousExpiresAt.isAfter(now)) {
                // Still-valid previous entry: this is a replay, keep the existing expiry.
                replay.set(true);
                return previousExpiresAt;
            }
            // No previous entry, or the previous entry already expired: treat as a first use.
            replay.set(false);
            return expiresAt;
        });

        if (registrationCount.incrementAndGet() % SWEEP_INTERVAL == 0) {
            sweep(now);
        }

        return replay.get();
    }

    /**
     * Returns the key an ID is stored under. The ID of an unsigned message is whatever the sender wrote,
     * and the cache keeps it for the whole validity window, so a long ID is replaced by its digest.
     *
     * @param id the ID of the message
     * @return the ID itself when it is short, otherwise the hex SHA-256 digest of it
     */
    private static String toKey(final String id) {
        if (id.length() <= MAX_KEY_LENGTH) {
            return id;
        }
        try {
            final byte[] digest = MessageDigest.getInstance("SHA-256").digest(id.getBytes(StandardCharsets.UTF_8));
            return "sha256:" + HexFormat.of().formatHex(digest);
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available.", e);
        }
    }

    /**
     * Opportunistically removes entries whose expiry is not after the given instant.
     *
     * @param now the instant to compare entry expiries against
     */
    private void sweep(final Instant now) {
        entries.entrySet().removeIf(entry -> !entry.getValue().isAfter(now));
    }

}
