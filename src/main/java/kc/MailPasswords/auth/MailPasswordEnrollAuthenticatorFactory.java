package kc.MailPasswords.auth;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class MailPasswordEnrollAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "mail-password-enroll-authenticator";

    @Override
    public String getDisplayType() {
        return "Enroll Mail Password";
    }

    @Override
    public String getReferenceCategory() {
        return "mail-password-enroll";
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new MailPasswordEnrollAuthenticator();
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Allows a user to generate a Mail Password (application-specific password).";
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
