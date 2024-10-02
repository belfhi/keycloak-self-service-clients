package de.mixxplorer.keycloak.ssc.rest;

import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import org.keycloak.services.cors.Cors;

// Return CORS response for all sub paths.
public class SelfServicePreflight {
    Cors cors;

    public SelfServicePreflight(Cors cors) {
        this.cors = cors;
    }

    @OPTIONS
    @Path("/{any:.*}")
    public Response answerCors() {
        return Cors.builder().auth().preflight().add(Response.ok());
    }
}
