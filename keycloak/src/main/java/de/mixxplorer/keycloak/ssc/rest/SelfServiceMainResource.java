package de.mixxplorer.keycloak.ssc.rest;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.cors.Cors;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import static de.mixxplorer.keycloak.ssc.Constants.SSC_CLIENT_ID;
import static de.mixxplorer.keycloak.ssc.Constants.SSC_MANAGER_CLIENT_ROLE;

public class SelfServiceMainResource {
    private final KeycloakSession keycloakSession;
    private Cors cors;

    public SelfServiceMainResource(KeycloakSession keycloakSession) {
        this.keycloakSession = keycloakSession;
    }

    // Main entry for self-service clients API
    @Path("")
    public Object getSelfServiceResources() {
        // Prepare CORS response
        final var httpRequest = keycloakSession.getContext().getHttpRequest();
        final var httpResponse = keycloakSession.getContext().getHttpResponse();

        cors = Cors.builder()
                .auth()
                .allowedMethods(HttpMethod.GET, HttpMethod.PUT, HttpMethod.POST, HttpMethod.DELETE)
                .auth()
                .exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS);

        // Do not continue, if the SSC_CLIENT_ID client is not available as this is an invalid configuration
        final var sscClient = this.keycloakSession.clients().getClientByClientId(
                this.keycloakSession.getContext().getRealm(), SSC_CLIENT_ID);
        if (sscClient == null) {
            cors.allowAllOrigins();
            throw new ForbiddenException(String.format("Self Service Clients not activated on this realm. "
                    + "Please ask your admin to create the %s client.", SSC_CLIENT_ID));
        }

        // Handle all CORS OPTIONS requests. As we are having the same CORS options for all routes, we return always
        // a valid CORS response, even if the route does not exist. This might be a bit misleading, but keeps
        // the code tidy. Furthermore, Keycloak is internally doing the same with its Admin API.
        // see also org.keycloak.services.resources.admin
        if (httpRequest.getHttpMethod().equalsIgnoreCase(HttpMethod.OPTIONS)) {
            return new SelfServicePreflight(cors);
        }

        // Check whether the user is authenticated. Doing this here ensures all requests forwarded to our real resources
        // are authenticated.
        AuthenticationManager.AuthResult authResult;
        try {
            authResult = checkPermissionsAndGetUser(sscClient);
        } catch (Exception exc) {
            cors.allowAllOrigins();
            throw exc;
        }

        // Add cors options to prepared response, which will be used (implicitly apparently) when building responses
        // downstream.
        cors.allowedOrigins(authResult.getToken()).add(Response.ok(httpResponse));

        return new SelfServiceResources(this.keycloakSession, authResult);
    }

    // Authenticate users centrally for all routes of the ssc API.
    // Users must be in the SSC_MANAGER_CLIENT_ROLE client role of client SSC_CLIENT_ID
    private AuthenticationManager.AuthResult checkPermissionsAndGetUser(ClientModel sscClient) {
        final var auth = new AppAuthManager.BearerTokenAuthenticator(this.keycloakSession);
        final var authResult = auth.authenticate();
        if (authResult == null) {
            throw new NotAuthorizedException("Not authorized");
        } else if (authResult.getToken().getRealmAccess() == null
                || authResult.getToken().getResourceAccess(sscClient.getClientId()) == null
                || !authResult.getToken().getResourceAccess(sscClient.getClientId()).isUserInRole(SSC_MANAGER_CLIENT_ROLE)) {
            throw new ForbiddenException(String.format("Token is missing the %s client role of client %s.",
                    SSC_MANAGER_CLIENT_ROLE, SSC_CLIENT_ID));
        }
        return authResult;
    }
}
