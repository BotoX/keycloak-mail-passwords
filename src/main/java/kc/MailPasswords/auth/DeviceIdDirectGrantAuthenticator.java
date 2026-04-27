package kc.MailPasswords.auth;

import kc.MailPasswords.cred.DeviceIdCredentialProvider;
import kc.MailPasswords.cred.DeviceIdCredentialProviderFactory;

import org.jboss.logging.Logger;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.*;

import jakarta.ws.rs.core.MultivaluedMap;

public class DeviceIdDirectGrantAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(MailPasswordEnrollAuthenticator.class);

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
            logger.warn("DeviceIdDirectGrantAuthenticator: No DeviceId in request");
            context.attempted();
            return;
        }

        String deviceType = params.getFirst("DeviceType");
        if (deviceType == null || deviceType.isEmpty()) {
            logger.warn("DeviceIdDirectGrantAuthenticator: No DeviceType in request");
            context.attempted();
            return;
        }

        RealmModel realm = context.getRealm();
        KeycloakSession session = context.getSession();
        DeviceIdCredentialProvider devProvider = (DeviceIdCredentialProvider)
                session.getProvider(CredentialProvider.class, DeviceIdCredentialProviderFactory.PROVIDER_ID);

        long lastUsedTime = devProvider.getDeviceIdLastUsedTime(realm, user, deviceId, deviceType);
        if (lastUsedTime == -1) {
            context.attempted();
            return;
        }

        context.getAuthenticationSession().setUserSessionNote("acr", "deviceId");

        context.success();
    }

    @Override public void action(AuthenticationFlowContext context) {}
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
    @Override public void close() {}
}
