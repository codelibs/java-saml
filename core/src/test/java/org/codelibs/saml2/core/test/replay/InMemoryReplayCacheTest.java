package org.codelibs.saml2.core.test.replay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.codelibs.saml2.core.replay.InMemoryReplayCache;
import org.codelibs.saml2.core.replay.ReplayCache;
import org.junit.Test;

/**
 * Tests for {@link InMemoryReplayCache}.
 */
public class InMemoryReplayCacheTest {

    /**
     * Tests the registerAndCheck method of InMemoryReplayCache
     * Case: first registration of an id is not a replay
     *
     * @see org.codelibs.saml2.core.replay.InMemoryReplayCache#registerAndCheck
     */
    @Test
    public void testFirstRegistrationIsNotReplay() {
        final ReplayCache cache = new InMemoryReplayCache();
        final boolean replay = cache.registerAndCheck("id-1", Instant.now().plusSeconds(300));
        assertFalse(replay);
    }

    /**
     * Tests the registerAndCheck method of InMemoryReplayCache
     * Case: second registration of the same, still-valid id is a replay
     *
     * @see org.codelibs.saml2.core.replay.InMemoryReplayCache#registerAndCheck
     */
    @Test
    public void testSecondRegistrationIsReplay() {
        final ReplayCache cache = new InMemoryReplayCache();
        final Instant expiresAt = Instant.now().plusSeconds(300);

        assertFalse(cache.registerAndCheck("id-2", expiresAt));
        assertTrue(cache.registerAndCheck("id-2", expiresAt));
    }

    /**
     * Tests the registerAndCheck method of InMemoryReplayCache
     * Case: an id whose previous entry already expired is treated as fresh
     *
     * @see org.codelibs.saml2.core.replay.InMemoryReplayCache#registerAndCheck
     */
    @Test
    public void testExpiredEntryIsTreatedAsFresh() {
        final ReplayCache cache = new InMemoryReplayCache();
        final Instant pastExpiry = Instant.now().minusSeconds(10);

        assertFalse(cache.registerAndCheck("id-3", pastExpiry));
        // Previous entry already expired, so this is treated as a fresh registration, not a replay.
        assertFalse(cache.registerAndCheck("id-3", Instant.now().plusSeconds(300)));
        // Now that it has been freshly re-registered with a future expiry, a further call is a replay.
        assertTrue(cache.registerAndCheck("id-3", Instant.now().plusSeconds(300)));
    }

    /**
     * Tests the registerAndCheck method of InMemoryReplayCache
     * Case: concurrent registration of the same id only allows a single caller to see "not a replay"
     *
     * @throws InterruptedException
     *
     * @see org.codelibs.saml2.core.replay.InMemoryReplayCache#registerAndCheck
     */
    @Test
    public void testConcurrentRegistrationSmoke() throws InterruptedException {
        final ReplayCache cache = new InMemoryReplayCache();
        final int threadCount = 16;
        final ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        final CountDownLatch ready = new CountDownLatch(threadCount);
        final CountDownLatch start = new CountDownLatch(1);
        final AtomicInteger firstUseCount = new AtomicInteger();
        final Instant expiresAt = Instant.now().plusSeconds(300);

        try {
            for (int i = 0; i < threadCount; i++) {
                executor.submit(() -> {
                    ready.countDown();
                    try {
                        start.await();
                    } catch (final InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                    if (!cache.registerAndCheck("concurrent-id", expiresAt)) {
                        firstUseCount.incrementAndGet();
                    }
                });
            }
            ready.await();
            start.countDown();
            executor.shutdown();
            assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS));
        } finally {
            executor.shutdownNow();
        }

        assertEquals(1, firstUseCount.get());
    }
}
