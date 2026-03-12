package kc.MailPasswords.ra;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import kc.MailPasswords.util.MailPasswordUtils;
import org.jboss.logging.Logger;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.validation.Validation;

/**
 * Required Action that lets a user generate a Mail App Password
 * through the (login) required action flow.
 */
public class MailPasswordRequiredAction implements RequiredActionProvider {

    private static final Logger logger = Logger.getLogger(MailPasswordRequiredAction.class);

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        String password = MailPasswordUtils.generateRandomPassword();
        context.getAuthenticationSession().setAuthNote(MailPasswordRequiredActionFactory.PROVIDER_ID, password);

        Response challenge = context.form()
            .setAttribute("generatedPassword", password)
            .createForm("mail-password-enroll.ftl");
        context.challenge(challenge);
    }

    @Override
    public void processAction(RequiredActionContext context) {
        MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();
        String password = context.getAuthenticationSession().getAuthNote(MailPasswordRequiredActionFactory.PROVIDER_ID);

        String userLabel = params.getFirst("userLabel");
        if (userLabel == null || userLabel.isEmpty()) {
            Response challenge = context.form()
                .addError(new FormMessage("userLabel", "missingTotpDeviceNameMessage"))
                .setAttribute("generatedPassword", password)
                .createForm("mail-password-enroll.ftl");
            context.challenge(challenge);
            return;
        }

        UserModel user = context.getUser();
        MailPasswordUtils.createMailAppPassword(context.getSession(), context.getRealm(), user, password, userLabel);
        context.success();
    }

    @Override
    public InitiatedActionSupport initiatedActionSupport() {
        return InitiatedActionSupport.SUPPORTED;
    }

    @Override
    public void close() {
        // no-op
    }
}
