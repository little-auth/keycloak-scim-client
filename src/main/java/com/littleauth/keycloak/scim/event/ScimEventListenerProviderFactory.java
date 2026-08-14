package com.littleauth.keycloak.scim.event;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory for {@link ScimEventListenerProvider}. Owns the shared executor that keeps
 * outbound SCIM calls off the synchronous Keycloak admin-request path (pre-mortem: a down
 * SCIM target must not turn into a Keycloak admin-console outage), and captures {@link
 * KeycloakSessionFactory} so dispatched jobs can open their own fresh session per Keycloak's
 * own background-job pattern rather than reusing the request-bound one.
 */
public class ScimEventListenerProviderFactory implements EventListenerProviderFactory {

  public static final String ID = "keycloak-scim-client";

  private ExecutorService executorService;
  private KeycloakSessionFactory sessionFactory;

  @Override
  public EventListenerProvider create(KeycloakSession session) {
    return new ScimEventListenerProvider(executorService, sessionFactory);
  }

  @Override
  public void init(Config.Scope config) {
    ThreadFactory threadFactory =
        runnable -> {
          Thread thread = new Thread(runnable, "keycloak-scim-client-dispatch");
          thread.setDaemon(true);
          return thread;
        };
    executorService = Executors.newFixedThreadPool(4, threadFactory);
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    this.sessionFactory = factory;
  }

  @Override
  public void close() {
    if (executorService != null) {
      executorService.shutdown();
    }
  }

  @Override
  public String getId() {
    return ID;
  }
}
