package kc.MailPasswords.auth;

import kc.MailPasswords.cred.DeviceIdCredentialProvider;
import kc.MailPasswords.cred.DeviceIdCredentialProviderFactory;

import org.jboss.logging.Logger;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.*;
import org.keycloak.util.JsonSerialization;
import org.keycloak.common.util.Time;
import org.keycloak.common.util.Base64Url;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

public class DeviceIdDirectGrantAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(MailPasswordEnrollAuthenticator.class);

    private static final int MAX_FAILURES = 5;
    private static final int LOCKOUT_DURATION = 300; // 5 minutes
    private static final String ATTRIBUTE_KEY = "DEVICEID_BRUTEFORCE";

    public static class BruteForceState {
        public int count = 0;
        public int until = 0;
        public String hash = "";
    }

    public Response errorResponse(int status, String error, String errorDescription) {
        OAuth2ErrorRepresentation errorRep = new OAuth2ErrorRepresentation(error, errorDescription);
        return Response.status(status).entity(errorRep).type(MediaType.APPLICATION_JSON_TYPE).build();
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user == null) {
            logger.warn("DeviceIdDirectGrantAuthenticator: No user in context");
            context.failure(AuthenticationFlowError.UNKNOWN_USER);
            return;
        }

        MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();
        String deviceId = params.getFirst("DeviceId");
        if (deviceId == null || deviceId.isEmpty()) {
            logger.debug("DeviceIdDirectGrantAuthenticator: No DeviceId in request");
            context.attempted();
            return;
        }

        String deviceType = params.getFirst("DeviceType");
        if (deviceType == null || deviceType.isEmpty()) {
            logger.debug("DeviceIdDirectGrantAuthenticator: No DeviceType in request");
            context.attempted();
            return;
        }

        int currentTime = Time.currentTime();
        String stateAttr = user.getFirstAttribute(ATTRIBUTE_KEY);

        BruteForceState state = new BruteForceState();
        if (stateAttr != null && !stateAttr.isEmpty()) {
            try {
                state = JsonSerialization.readValue(stateAttr, BruteForceState.class);
            } catch (IOException e) {
                logger.error("DeviceIdDirectGrantAuthenticator: Failed to parse corrupted brute-force JSON state attribute", e);
            }
        }

        if (currentTime < state.until) {
            Response res = errorResponse(401, "invalid_grant", "User temporarily disabled");
            context.failure(AuthenticationFlowError.USER_TEMPORARILY_DISABLED, res);
            return;
        }

        RealmModel realm = context.getRealm();
        KeycloakSession session = context.getSession();
        DeviceIdCredentialProvider devProvider = (DeviceIdCredentialProvider)
                session.getProvider(CredentialProvider.class, DeviceIdCredentialProviderFactory.PROVIDER_ID);

        long lastUsedTime = devProvider.getDeviceIdLastUsedTime(realm, user, deviceId, deviceType);
        if (lastUsedTime == -1) {
            String deviceHash = hashDeviceId(deviceType, deviceId);
            if (!deviceHash.equals(state.hash)) {
                state.hash = deviceHash;

                if (state.until > 0 && currentTime >= state.until) {
                    state.count = 1;
                    state.until = 0;
                } else {
                    state.count++;
                }

                if (state.count >= MAX_FAILURES) {
                    state.until = currentTime + LOCKOUT_DURATION;
                }

                try {
                    String jsonString = JsonSerialization.writeValueAsString(state);
                    user.setAttribute(ATTRIBUTE_KEY, Collections.singletonList(jsonString));
                } catch (IOException e) {
                    logger.error("DeviceIdDirectGrantAuthenticator: Failed to write brute-force JSON state attribute", e);
                }
            }

            context.success();
            return;
        }

        context.getAuthenticationSession().setUserSessionNote("acr", "deviceId");

        user.removeAttribute(ATTRIBUTE_KEY);
        context.success();
    }

    private String hashDeviceId(String deviceType, String deviceId) {
        try {
            String combined = deviceType + ":" + deviceId;
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            digest.update(deviceType.getBytes(StandardCharsets.UTF_8));
            digest.update(deviceId.getBytes(StandardCharsets.UTF_8));
            return Base64Url.encode(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override public void action(AuthenticationFlowContext context) {}
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
    @Override public void close() {}
}
