package kc.MailPasswords.cred;

import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

public class DeviceIdCredentialProviderFactory implements CredentialProviderFactory<DeviceIdCredentialProvider> {

    public static final String PROVIDER_ID = "activesync-deviceid";

    @Override
    public DeviceIdCredentialProvider create(KeycloakSession session) {
        return new DeviceIdCredentialProvider(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
