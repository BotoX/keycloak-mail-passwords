package kc.MailPasswords.cred;

import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

public class MailPasswordCredentialProviderFactory implements CredentialProviderFactory<MailPasswordCredentialProvider> {

    public static final String PROVIDER_ID = "mail-password";

    @Override
    public MailPasswordCredentialProvider create(KeycloakSession session) {
        return new MailPasswordCredentialProvider(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
