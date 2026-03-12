package kc.MailPasswords.auth;

import kc.MailPasswords.cred.MailPasswordCredentialProvider;
import kc.MailPasswords.cred.MailPasswordCredentialProviderFactory;
import kc.MailPasswords.cred.MailPasswordCredentialModel;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.*;

import jakarta.ws.rs.core.MultivaluedMap;

public class MailPasswordDirectGrantAuthenticator implements Authenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user == null) {
            context.failure(AuthenticationFlowError.UNKNOWN_USER);
            return;
        }

        MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();
        String password = params.getFirst("password");
        if (password == null) {
            context.attempted();
            return;
        }

        RealmModel realm = context.getRealm();
        KeycloakSession session = context.getSession();

        MailPasswordCredentialProvider provider =
                (MailPasswordCredentialProvider) session.getProvider(
                        CredentialProvider.class,
                        MailPasswordCredentialProviderFactory.PROVIDER_ID);

        CredentialInput input = new UserCredentialModel(
                user.getUsername(),
                MailPasswordCredentialModel.TYPE,
                password
        );

        boolean ok = provider.isValid(realm, user, input);
        if (!ok) {
            context.attempted(); // allow Password+DeviceID path to be tried
            return;
        }

        context.getAuthenticationSession().setUserSessionNote("acr", "mail-password");

        context.success();
    }

    @Override public void action(AuthenticationFlowContext context) {}
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
    @Override public void close() {}
}
