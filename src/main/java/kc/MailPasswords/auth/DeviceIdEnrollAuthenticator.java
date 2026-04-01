package kc.MailPasswords.auth;

import static kc.MailPasswords.auth.DeviceIdEnrollAuthenticatorFactory.CONF_JWT_AUD;
import static kc.MailPasswords.auth.DeviceIdEnrollAuthenticatorFactory.CONF_JWT_ISS;
import static kc.MailPasswords.auth.DeviceIdEnrollAuthenticatorFactory.CONF_JWT_SECRET;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import kc.MailPasswords.cred.DeviceIdCredentialProvider;
import kc.MailPasswords.cred.DeviceIdCredentialProviderFactory;

public class DeviceIdEnrollAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(MailPasswordEnrollAuthenticator.class);

    private static final String TOKEN_PARAM = "enroll_token";

    public record TokenResult(String deviceId, String deviceType, String subject) {}

    private static TokenResult parseToken(AuthenticationFlowContext context) {
        AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
        if (authenticatorConfig == null) {
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
            logger.warn("DeviceIdEnrollAuthenticator: No authenticator config in context");
            return null;
        }

        MultivaluedMap<String, String> q = context.getHttpRequest().getUri().getQueryParameters();
        String token = q.getFirst(TOKEN_PARAM);
        if (token == null) {
            // No token -> nothing to enroll
            logger.warnf("DeviceIdEnrollAuthenticator: No '%s' in request", TOKEN_PARAM);
            context.attempted();
            return null;
        }

        Map<String, String> config = authenticatorConfig.getConfig();

        String subject;
        String deviceId;
        String deviceType;
        try {
            Claims claims = Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(config.get(CONF_JWT_SECRET).getBytes(StandardCharsets.UTF_8)))
                .requireIssuer(config.get(CONF_JWT_ISS))
                .requireAudience(config.get(CONF_JWT_AUD))
                .build()
                .parseSignedClaims(token)
                .getPayload();
            subject = claims.getSubject();
            deviceId = claims.get("DeviceId", String.class);
            deviceType = claims.get("DeviceType", String.class);
        } catch (Exception e) {
            logger.warn("DeviceIdEnrollAuthenticator: Error parsing JWT token", e);
            return null;
        }

        if (subject == null || subject.isEmpty()) {
            logger.warn("DeviceIdEnrollAuthenticator: No subject claim in token");
            context.attempted();
            return null;
        }

        if (deviceId == null || deviceId.isEmpty()) {
            logger.warn("DeviceIdEnrollAuthenticator: No DeviceId claim in token");
            context.attempted();
            return null;
        }

        if (deviceType == null || deviceType.isEmpty()) {
            logger.warn("DeviceIdEnrollAuthenticator: No DeviceType claim in token");
            context.attempted();
            return null;
        }

        return new TokenResult(deviceId, deviceType, subject);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user == null) {
            context.failure(AuthenticationFlowError.UNKNOWN_USER);
            logger.warn("DeviceIdEnrollAuthenticator: No user in context");
            return;
        }

        TokenResult tokenResult = parseToken(context);
        if (tokenResult == null) {
            return;
        }

        String username = user.getUsername();
        boolean match = tokenResult.subject().equalsIgnoreCase(username);

        if (!match) {
            logger.warnf("DeviceIdEnrollAuthenticator: Subject '%s' does not match username '%s'", tokenResult.subject(), username);
            context.attempted();
            return;
        }

        RealmModel realm = context.getRealm();
        KeycloakSession session = context.getSession();

        DeviceIdCredentialProvider provider = (DeviceIdCredentialProvider)
                session.getProvider(CredentialProvider.class, DeviceIdCredentialProviderFactory.PROVIDER_ID);

        long lastUsedTime = provider.getDeviceIdLastUsedTime(realm, user, tokenResult.deviceId(), tokenResult.deviceType());
        if (lastUsedTime != -1) {
            // Device already exists
            context.success();
            return;
        }

        // Show confirmation page
        LoginFormsProvider forms = context.form();
        forms.setAttribute("deviceId", tokenResult.deviceId());
        forms.setAttribute("deviceType", tokenResult.deviceType());

        Response challenge = forms.createForm("deviceid-enroll.ftl");
        context.challenge(challenge);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();

        TokenResult tokenResult = parseToken(context);
        if (tokenResult == null) {
            return;
        }

        String userLabel = params.getFirst("userLabel");
        if (userLabel == null || userLabel.isEmpty()) {
            Response challenge = context.form()
                .addError(new FormMessage("userLabel", "missingTotpDeviceNameMessage"))
                .setAttribute("deviceId", tokenResult.deviceId())
                .setAttribute("deviceType", tokenResult.deviceType())
                .createForm("deviceid-enroll.ftl");
            context.challenge(challenge);
            return;
        }

        RealmModel realm = context.getRealm();
        KeycloakSession session = context.getSession();
        UserModel user = context.getUser();

        DeviceIdCredentialProvider provider = (DeviceIdCredentialProvider)
                session.getProvider(CredentialProvider.class, DeviceIdCredentialProviderFactory.PROVIDER_ID);

        long lastUsedTime = provider.getDeviceIdLastUsedTime(realm, user, tokenResult.deviceId(), tokenResult.deviceType());
        if (lastUsedTime != -1) {
            // Device already exists
            context.success();
            return;
        }

        provider.createDeviceIdCredential(realm, user, tokenResult.deviceId(), tokenResult.deviceType(), userLabel);

        context.success();
    }

    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
    @Override public void close() {}
}
