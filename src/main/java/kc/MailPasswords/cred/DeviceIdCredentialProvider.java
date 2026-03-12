package kc.MailPasswords.cred;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialMetadata;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.models.*;

import java.time.Instant;
import java.time.ZoneId;
import java.util.LinkedList;
import java.util.List;
import java.time.format.DateTimeFormatter;

public class DeviceIdCredentialProvider implements CredentialProvider<DeviceIdCredentialModel> {

    private static final Logger logger = Logger.getLogger(MailPasswordCredentialProvider.class);
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
      .withZone(ZoneId.of("UTC"));

    private final KeycloakSession session;

    public DeviceIdCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, DeviceIdCredentialModel credentialModel) {
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
    public DeviceIdCredentialModel getCredentialFromModel(CredentialModel model) {
        return DeviceIdCredentialModel.createFromCredentialModel(model);
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return DeviceIdCredentialModel.TYPE.equals(credentialType);
    }

    @Override
    public String getType() {
        return DeviceIdCredentialModel.TYPE;
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext metadataContext) {
        return CredentialTypeMetadata.builder()
                .type(getType())
                .category(CredentialTypeMetadata.Category.TWO_FACTOR)
                .displayName("ActiveSync Trusted Device")
                .helpText("Trusted ActiveSync DeviceID.")
                .removeable(true)
                .build(session);
    }

    @Override
    public CredentialMetadata getCredentialMetadata(DeviceIdCredentialModel credentialModel, CredentialTypeMetadata credentialTypeMetadata) {
        CredentialMetadata credentialMetadata = new CredentialMetadata();
        List<CredentialMetadata.LocalizedMessage> properties = new LinkedList<>();

        DeviceIdCredentialModel deviceIdModel = DeviceIdCredentialModel.createFromCredentialModel(credentialModel);
        DeviceIdCredentialData data = deviceIdModel.getDeviceIdCredentialData();

        properties.add(new CredentialMetadata.LocalizedMessage("Device ID",
            new String[] { data.getDeviceId() }));
        properties.add(new CredentialMetadata.LocalizedMessage("Device Type",
            new String[] { data.getDeviceType() }));
        properties.add(new CredentialMetadata.LocalizedMessage("lastAccessedOn",
            new String[] { formatter.format(Instant.ofEpochMilli(data.getlastUsedTime())) }));

        credentialMetadata.setInfoProperties(properties);

        credentialMetadata.setCredentialModel(credentialModel);
        return credentialMetadata;
    }

    public long getDeviceIdLastUsedTime(RealmModel realm, UserModel user, String deviceId, String deviceType) {
        List<CredentialModel> creds = user.credentialManager()
                .getStoredCredentialsByTypeStream(DeviceIdCredentialModel.TYPE)
                .toList();
        for (CredentialModel c : creds) {
            DeviceIdCredentialModel dev = DeviceIdCredentialModel.createFromCredentialModel(c);
            if (deviceId.equals(dev.getDeviceIdCredentialData().getDeviceId()) && deviceType.equals(dev.getDeviceIdCredentialData().getDeviceType())) {
                long lastUsedTime = dev.getDeviceIdCredentialData().getlastUsedTime();
                dev.updateLastUsed();
                user.credentialManager().updateStoredCredential(dev);
                return lastUsedTime;
            }
        }
        return -1;
    }

    public DeviceIdCredentialModel createDeviceIdCredential(RealmModel realm, UserModel user, String deviceId, String deviceType, String userLabel) {
        DeviceIdCredentialModel model = DeviceIdCredentialModel.create(deviceId, deviceType, userLabel);
        user.credentialManager().createStoredCredential(model);
        return model;
    }

    public List<CredentialModel> getAllDeviceCredentials(RealmModel realm, UserModel user) {
        return user.credentialManager()
                .getStoredCredentialsByTypeStream(DeviceIdCredentialModel.TYPE)
                .toList();
    }
}
