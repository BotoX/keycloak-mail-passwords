package kc.MailPasswords.util;

import java.util.Random;

import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import kc.MailPasswords.cred.MailPasswordCredentialModel;

public final class MailPasswordUtils {

    private MailPasswordUtils() {
    }

    public static String generateRandomPassword() {
        int len = 32;
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder(len);
        Random rnd = new Random();
        for (int i = 0; i < len; i++) {
            sb.append(chars.charAt(rnd.nextInt(chars.length())));
        }
        return sb.toString();
    }

    public static CredentialModel createMailAppPassword(KeycloakSession session, RealmModel realm, UserModel user,
            String password, String label) {
        MailPasswordCredentialModel model = MailPasswordCredentialModel.create(session, realm, password, label);
        user.credentialManager().createStoredCredential(model);
        return model;
    }
}
