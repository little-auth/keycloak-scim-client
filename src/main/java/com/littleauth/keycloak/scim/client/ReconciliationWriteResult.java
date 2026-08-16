package com.littleauth.keycloak.scim.client;

import de.captaingoldfish.scim.sdk.client.response.ServerResponse;
import de.captaingoldfish.scim.sdk.common.resources.User;

/**
 * Outcome of {@link ScimTargetClient#replaceIfVersionUnchanged}: whether a reconciliation
 * diff-derived write actually landed, was skipped because the target changed since it was
 * read (issue #6's N6/N7 race mitigation), or failed outright.
 */
public record ReconciliationWriteResult(Outcome outcome, ServerResponse<User> response) {

  /** What happened when reconciliation tried to apply a diff-derived write. */
  public enum Outcome {
    /** The write was sent and the target accepted it. */
    APPLIED,
    /**
     * The target rejected the write as a version conflict (412/409) -- something else wrote
     * to this resource since reconciliation last read it. Skipped, not overwritten; the next
     * pass will re-diff against the now-current state.
     */
    VERSION_CONFLICT,
    /** The write failed for an unrelated reason (network, server error, ...). */
    FAILED
  }
}
