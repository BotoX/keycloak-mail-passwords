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

public class DeviceIdEnrollAuthenticatorFactory implements AuthenticatorFactory {

    public static final String ID = "deviceid-enroll-authenticator";

    public static final String CONF_JWT_SECRET = "jwt-secret";
    public static final String CONF_JWT_ISS = "jwt-iss";
    public static final String CONF_JWT_AUD = "jwt-aud";

    public static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty jwtSecret = new ProviderConfigProperty();
        jwtSecret.setType(ProviderConfigProperty.STRING_TYPE);
        jwtSecret.setName(CONF_JWT_SECRET);
        jwtSecret.setLabel("JWT Secret");
        jwtSecret.setDefaultValue("");
        jwtSecret.setHelpText(
            "The secret used to sign the JWT token.");
        CONFIG_PROPERTIES.add(jwtSecret);

        ProviderConfigProperty jwtIssuer = new ProviderConfigProperty();
        jwtIssuer.setType(ProviderConfigProperty.STRING_TYPE);
        jwtIssuer.setName(CONF_JWT_ISS);
        jwtIssuer.setLabel("JWT Issuer");
        jwtIssuer.setDefaultValue("");
        jwtIssuer.setHelpText(
            "The issuer of the JWT token.");
        CONFIG_PROPERTIES.add(jwtIssuer);

        ProviderConfigProperty jwtAud = new ProviderConfigProperty();
        jwtAud.setType(ProviderConfigProperty.STRING_TYPE);
        jwtAud.setName(CONF_JWT_AUD);
        jwtAud.setLabel("JWT Audience");
        jwtAud.setDefaultValue("");
        jwtAud.setHelpText(
            "The audience of the JWT token.");
        CONFIG_PROPERTIES.add(jwtAud);
    }

    @Override
    public String getDisplayType() {
        return "Enroll ActiveSync DeviceID";
    }

    @Override
    public String getReferenceCategory() {
        return "activesync-deviceid-enroll";
    }

    @Override
    public boolean isConfigurable() { return true; }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new DeviceIdEnrollAuthenticator();
    }

    @Override public void init(Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getHelpText() {
        return "Enrolls a trusted ActiveSync DeviceID using a JWT link.";
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
        return CONFIG_PROPERTIES;
    }
}
