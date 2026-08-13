package com.littleauth.keycloak.scim.config;

/** Thrown when a configured SCIM target URL is rejected by {@link TargetUrlValidator}. */
public class InvalidTargetUrlException extends RuntimeException {

  /** Rejects a SCIM target URL with the given human-readable reason. */
  public InvalidTargetUrlException(String message) {
    super(message);
  }

  /** Rejects a SCIM target URL with the given reason and underlying cause. */
  public InvalidTargetUrlException(String message, Throwable cause) {
    super(message, cause);
  }
}
