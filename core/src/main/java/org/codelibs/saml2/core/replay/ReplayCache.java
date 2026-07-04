package org.codelibs.saml2.core.replay;

import java.time.Instant;

/**
 * Thread-safe store for detecting replayed SAML message/assertion IDs.
 * Implementations MUST be thread-safe.
 */
public interface ReplayCache {

    /**
     * Atomically records the id if unseen and reports whether it was already present.
     *
     * @param id the assertion or message ID
     * @param expiresAt instant after which the entry may be evicted (never null)
     * @return true if id was already registered (=&gt; replay); false if newly registered (first use)
     */
    boolean registerAndCheck(String id, Instant expiresAt);

}
