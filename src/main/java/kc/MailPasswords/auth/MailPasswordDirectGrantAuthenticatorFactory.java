package kc.MailPasswords.auth;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class MailPasswordDirectGrantAuthenticatorFactory implements AuthenticatorFactory {

    public static final String ID = "mail-password-direct-grant";

    @Override
    public String getDisplayType() {
        return "Mail Password";
    }

    @Override
    public String getReferenceCategory() {
        return "mail-password";
    }

    @Override
    public boolean isConfigurable() { return false; }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new MailPasswordDirectGrantAuthenticator();
    }

    @Override
    public void init(Config.Scope config) {}
    @Override
    public void postInit(KeycloakSessionFactory factory) {}
    @Override
    public void close() {}

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getHelpText() {
        return "Validates the mail-password supplied as a 'password' form parameter in direct grant request";
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }
}
