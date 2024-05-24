package de.mixxplorer.keycloak.ssc.rest;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class SelfServiceProviderFactory implements RealmResourceProviderFactory {
    @Override
    public RealmResourceProvider create(KeycloakSession keycloakSession) {
        return new SelfService(keycloakSession);
    }

    @Override
    public void init(Config.Scope scope) {}

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {}

    @Override
    public void close() {}

    @Override
    public String getId() {
        return "self-service-clients";
    }
}
