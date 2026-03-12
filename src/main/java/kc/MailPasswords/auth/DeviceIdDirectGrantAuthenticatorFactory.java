package kc.MailPasswords.auth;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class DeviceIdDirectGrantAuthenticatorFactory implements AuthenticatorFactory {

    public static final String ID = "deviceid-direct-grant";

    @Override
    public String getDisplayType() {
        return "ActiveSync DeviceID";
    }

    @Override
    public String getReferenceCategory() {
        return "activesync-deviceid";
    }

    @Override
    public boolean isConfigurable() { return false; }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new DeviceIdDirectGrantAuthenticator();
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
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
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

    @Override
    public String getHelpText() {
        return "Validates the ActiveSync Device ID and Device Type supplied as 'DeviceId' and 'DeviceType' form parameters in direct grant request";
    }
}
