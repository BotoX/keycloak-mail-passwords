package kc.MailPasswords.cred;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.credential.*;
import org.keycloak.models.*;
import org.keycloak.models.credential.PasswordCredentialModel;

import kc.MailPasswords.ra.MailPasswordRequiredActionFactory;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.LinkedList;
import java.util.List;

public class MailPasswordCredentialProvider
        implements CredentialProvider<MailPasswordCredentialModel>, CredentialInputValidator {

    private static final Logger logger = Logger.getLogger(MailPasswordCredentialProvider.class);
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault());

    private final KeycloakSession session;

    public MailPasswordCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user,
            MailPasswordCredentialModel credentialModel) {
        if (credentialModel.getCreatedDate() == null) {
            credentialModel.setCreatedDate(Time.currentTimeMillis());
        }
        return user.credentialManager().createStoredCredential(credentialModel);
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        return user.credentialManager().removeStoredCredentialById(credentialId);
    }

    @Override
    public MailPasswordCredentialModel getCredentialFromModel(CredentialModel model) {
        return MailPasswordCredentialModel.createFromCredentialModel(model);
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return MailPasswordCredentialModel.TYPE.equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        if (!supportsCredentialType(credentialType))
            return false;
        return user.credentialManager()
                .getStoredCredentialsByTypeStream(MailPasswordCredentialModel.TYPE)
                .findAny().isPresent();
    }

    public boolean isConfiguredFor(RealmModel realm, UserModel user) {
        return isConfiguredFor(realm, user, getType());
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!(input instanceof UserCredentialModel)) {
            return false;
        }
        if (!supportsCredentialType(input.getType())) {
            return false;
        }

        String candidate = input.getChallengeResponse();
        if (candidate == null) {
            return false;
        }

        // validate against all mail-password credentials
        List<CredentialModel> creds = user.credentialManager()
                .getStoredCredentialsByTypeStream(MailPasswordCredentialModel.TYPE)
                .toList();

        for (CredentialModel c : creds) {
            MailPasswordCredentialModel m = MailPasswordCredentialModel.createFromCredentialModel(c);
            if (m.verify(session, candidate)) {
                m.updateLastUsed();
                user.credentialManager().updateStoredCredential(m);
                return true;
            }
        }
        return false;
    }

    @Override
    public String getType() {
        return MailPasswordCredentialModel.TYPE;
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext metadataContext) {
        return CredentialTypeMetadata.builder()
                .type(getType())
                .category(CredentialTypeMetadata.Category.BASIC_AUTHENTICATION)
                .displayName("mail-password-display-name")
                .helpText("mail-password-help-text")
                .iconCssClass("kcAuthenticatorPasswordClass")
                .createAction(MailPasswordRequiredActionFactory.PROVIDER_ID)
                .removeable(true)
                .build(session);
    }

    @Override
    public CredentialMetadata getCredentialMetadata(MailPasswordCredentialModel credentialModel,
            CredentialTypeMetadata credentialTypeMetadata) {
        CredentialMetadata credentialMetadata = new CredentialMetadata();
        List<CredentialMetadata.LocalizedMessage> properties = new LinkedList<>();

        PasswordCredentialModel pwModel = PasswordCredentialModel.createFromCredentialModel(credentialModel);
        pwModel.getPasswordCredentialData().getAdditionalParameters()
                .get(MailPasswordCredentialModel.PARAM_LAST_USED_TIME).stream().findFirst()
                .ifPresent(lastUsed -> properties.add(new CredentialMetadata.LocalizedMessage("lastAccessedOn",
                        new String[] { formatter.format(Instant.ofEpochMilli(Long.parseLong(lastUsed))) })));

        credentialMetadata.setInfoProperties(properties);

        credentialMetadata.setCredentialModel(credentialModel);
        return credentialMetadata;
    }
}
