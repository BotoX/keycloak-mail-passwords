package kc.MailPasswords.auth;

import kc.MailPasswords.util.MailPasswordUtils;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

public class MailPasswordEnrollAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(MailPasswordEnrollAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user == null) {
            context.failure(AuthenticationFlowError.UNKNOWN_USER);
            return;
        }

        String password = MailPasswordUtils.generateRandomPassword();
        context.getAuthenticationSession().setAuthNote(MailPasswordEnrollAuthenticatorFactory.PROVIDER_ID, password);

        Response challenge = context.form()
            .setAttribute("generatedPassword", password)
            .createForm("mail-password-enroll.ftl");
        context.challenge(challenge);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user == null) {
            context.failure(AuthenticationFlowError.UNKNOWN_USER);
            return;
        }

        MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();
        String password = context.getAuthenticationSession().getAuthNote(MailPasswordEnrollAuthenticatorFactory.PROVIDER_ID);

        String userLabel = params.getFirst("userLabel");
        if (userLabel == null || userLabel.isEmpty()) {
            Response challenge = context.form()
                .addError(new FormMessage("userLabel", "missingTotpDeviceNameMessage"))
                .setAttribute("generatedPassword", password)
                .createForm("mail-password-enroll.ftl");
            context.challenge(challenge);
            return;
        }

        MailPasswordUtils.createMailAppPassword(context.getSession(), context.getRealm(), user, password, userLabel);
        context.success();
    }

    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
    @Override public void close() {}
}
