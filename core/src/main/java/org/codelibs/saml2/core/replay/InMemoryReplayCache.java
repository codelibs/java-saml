package org.codelibs.saml2.core.replay;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Default in-memory, thread-safe {@link ReplayCache} implementation backed by a
 * {@link ConcurrentHashMap}. Expired entries are evicted opportunistically (no
 * background threads are started by this class).
 */
public class InMemoryReplayCache implements ReplayCache {

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

        entries.compute(id, (key, previousExpiresAt) -> {
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
     * Opportunistically removes entries whose expiry is not after the given instant.
     *
     * @param now the instant to compare entry expiries against
     */
    private void sweep(final Instant now) {
        entries.entrySet().removeIf(entry -> !entry.getValue().isAfter(now));
    }

}
