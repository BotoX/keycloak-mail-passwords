package kc.MailPasswords.cred;

import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

public class DeviceIdCredentialModel extends CredentialModel {

    public static final String TYPE = "activesync-deviceid";

    private DeviceIdCredentialData credentialData;

    private DeviceIdCredentialModel(DeviceIdCredentialData data) {
        this.credentialData = data;
    }

    public static DeviceIdCredentialModel create(String deviceId, String deviceType, String userLabel) {
        DeviceIdCredentialData data = new DeviceIdCredentialData(deviceId, deviceType, 0L);
        DeviceIdCredentialModel model = new DeviceIdCredentialModel(data);
        model.fillCredentialModelFields();
        model.setUserLabel(userLabel);
        return model;
    }

    public static DeviceIdCredentialModel createFromCredentialModel(CredentialModel credentialModel) {
        try {
            DeviceIdCredentialData data = JsonSerialization.readValue(
                    credentialModel.getCredentialData(), DeviceIdCredentialData.class);

            DeviceIdCredentialModel model = new DeviceIdCredentialModel(data);
            model.setId(credentialModel.getId());
            model.setCreatedDate(credentialModel.getCreatedDate());
            model.setUserLabel(credentialModel.getUserLabel());
            model.setType(TYPE);
            model.setSecretData(credentialModel.getSecretData());
            model.setCredentialData(credentialModel.getCredentialData());
            return model;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void fillCredentialModelFields() {
        try {
            setCredentialData(JsonSerialization.writeValueAsString(credentialData));
            setSecretData("{}");
            setType(TYPE);
            setCreatedDate(Time.currentTimeMillis());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public DeviceIdCredentialData getDeviceIdCredentialData() {
        return credentialData;
    }

    public void updateLastUsed() {
        credentialData.setlastUsedTime(Time.currentTimeMillis());
        try {
            setCredentialData(JsonSerialization.writeValueAsString(credentialData));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
