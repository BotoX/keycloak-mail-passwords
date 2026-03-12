package kc.MailPasswords.cred;

import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.credential.dto.PasswordCredentialData;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MailPasswordCredentialModel extends CredentialModel {

    public static final String TYPE = "mail-password";
    public static final String PARAM_LAST_USED_TIME = "lastUsedTime";

    private PasswordCredentialModel delegate;

    private MailPasswordCredentialModel(PasswordCredentialModel delegate) {
        this.delegate = delegate;
    }

    /**
     * Create a mail password credential using the realm password policy and PasswordHashProvider.
     */
    public static MailPasswordCredentialModel create(KeycloakSession session,
                                                     RealmModel realm,
                                                     String plainPassword,
                                                     String label) {
        long now = Time.currentTimeMillis();

        PasswordPolicy policy = realm.getPasswordPolicy();
        PasswordHashProvider hashProvider = getHashProvider(session, policy);

        // Use PasswordCredentialModel factory; we’ll tweak additionalParameters afterwards
        PasswordCredentialModel pwModel = hashProvider.encodedCredential(
                plainPassword,
                policy != null ? policy.getHashIterations() : -1
        );
        pwModel.setCreatedDate(now);

        // Add our lastUsedAt = 0 in additionalParameters
        PasswordCredentialData pwdData = pwModel.getPasswordCredentialData();
        Map<String, List<String>> additional = pwdData.getAdditionalParameters();
        if (additional == null) {
            additional = Collections.emptyMap();
        }

        // safely copy & extend map
        java.util.Map<String, List<String>> newAdditional = new java.util.HashMap<>(additional);
        newAdditional.put(PARAM_LAST_USED_TIME, Collections.singletonList("0"));

        PasswordCredentialData newPwdData = new PasswordCredentialData(
                pwdData.getHashIterations(),
                pwdData.getAlgorithm(),
                newAdditional
        );

        try {
            pwModel.setCredentialData(JsonSerialization.writeValueAsString(newPwdData));
        } catch (IOException e) {
            throw new RuntimeException("Failed to serialize PasswordCredentialData for mail password", e);
        }

        // Wrap into our MailPasswordCredentialModel backed by the same JSON
        MailPasswordCredentialModel model = new MailPasswordCredentialModel(pwModel);
        // Copy fields into this CredentialModel
        model.setId(pwModel.getId());
        model.setCreatedDate(pwModel.getCreatedDate());
        model.setUserLabel(label);
        model.setType(TYPE);
        model.setCredentialData(pwModel.getCredentialData());
        model.setSecretData(pwModel.getSecretData());
        return model;
    }

    /**
     * Rebuild from a stored CredentialModel.
     */
    public static MailPasswordCredentialModel createFromCredentialModel(CredentialModel credentialModel) {
        // Let PasswordCredentialModel parse the full JSON (PasswordCredentialData + PasswordSecretData)
        PasswordCredentialModel pwModel = PasswordCredentialModel.createFromCredentialModel(credentialModel);

        MailPasswordCredentialModel model = new MailPasswordCredentialModel(pwModel);
        model.setId(credentialModel.getId());
        model.setCreatedDate(credentialModel.getCreatedDate());
        model.setUserLabel(credentialModel.getUserLabel());
        model.setType(TYPE);
        model.setSecretData(credentialModel.getSecretData());
        model.setCredentialData(credentialModel.getCredentialData());
        return model;
    }

    private static PasswordHashProvider getHashProvider(KeycloakSession session, PasswordPolicy policy) {
        if (policy != null && policy.getHashAlgorithm() != null) {
            PasswordHashProvider provider = session.getProvider(PasswordHashProvider.class, policy.getHashAlgorithm());
            if (provider != null) {
                return provider;
            }
        }
        return session.getProvider(PasswordHashProvider.class);
    }

    public PasswordCredentialModel getDelegate() {
        return delegate;
    }

    /**
     * Reads lastUsedAt from additionalParameters.
     * Returns 0 if not present or parse error.
     */
    public long getLastUsedAt() {
        PasswordCredentialData pwdData = delegate.getPasswordCredentialData();
        if (pwdData.getAdditionalParameters() == null) {
            return 0L;
        }
        List<String> values = pwdData.getAdditionalParameters().get(PARAM_LAST_USED_TIME);
        if (values == null || values.isEmpty()) {
            return 0L;
        }
        try {
            return Long.parseLong(values.get(0));
        } catch (NumberFormatException e) {
            return 0L;
        }
    }

    /**
     * Updates lastUsedAt in additionalParameters and writes it back to credentialData JSON.
     */
    public void updateLastUsed() {
        PasswordCredentialData pwdData = delegate.getPasswordCredentialData();
        Map<String, List<String>> additional = pwdData.getAdditionalParameters();
        if (additional == null) {
            additional = Collections.emptyMap();
        }

        long now = Instant.now().toEpochMilli();

        java.util.Map<String, List<String>> newAdditional = new java.util.HashMap<>(additional);
        newAdditional.put(PARAM_LAST_USED_TIME, Collections.singletonList(Long.toString(now)));

        PasswordCredentialData newPwdData = new PasswordCredentialData(
                pwdData.getHashIterations(),
                pwdData.getAlgorithm(),
                newAdditional
        );

        try {
            String json = JsonSerialization.writeValueAsString(newPwdData);
            delegate.setCredentialData(json);
            this.setCredentialData(json);
        } catch (IOException e) {
            throw new RuntimeException("Failed to update lastUsedAt in PasswordCredentialData", e);
        }
    }

    /**
     * Verify the candidate password using PasswordHashProvider and the delegate model.
     */
    public boolean verify(KeycloakSession session, String candidate) {
        String algorithm = delegate.getPasswordCredentialData().getAlgorithm();
        PasswordHashProvider hash = session.getProvider(PasswordHashProvider.class, algorithm);
        if (hash == null) {
            return false;
        }
        return hash.verify(candidate, delegate);
    }
}
