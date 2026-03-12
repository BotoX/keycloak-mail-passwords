package kc.MailPasswords.ra;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class MailPasswordRequiredActionFactory implements RequiredActionFactory {

    private static final MailPasswordRequiredAction INSTANCE = new MailPasswordRequiredAction();

    public static final String PROVIDER_ID = "mail-password-enroll-action";

    @Override
    public String getDisplayText() {
        return "Create Mail App Password";
    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return INSTANCE;
    }

    @Override
    public void init(Config.Scope config) { }

    @Override
    public void postInit(KeycloakSessionFactory factory) { }

    @Override
    public void close() { }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
