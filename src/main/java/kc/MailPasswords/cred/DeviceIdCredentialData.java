package kc.MailPasswords.cred;

public class DeviceIdCredentialData {
    private String deviceId;
    private String deviceType;
    private long lastUsedTime;

    public DeviceIdCredentialData() {}

    public DeviceIdCredentialData(String deviceId, String deviceType, long lastUsedTime) {
        this.deviceId = deviceId;
        this.deviceType = deviceType;
        this.lastUsedTime = lastUsedTime;
    }

    public String getDeviceId() { return deviceId; }
    public void setDeviceId(String deviceId) { this.deviceId = deviceId; }

    public String getDeviceType() { return deviceType; }
    public void setDeviceType(String deviceType) { this.deviceType = deviceType; }

    public long getLastUsedTime() { return lastUsedTime; }
    public void setLastUsedTime(long lastUsedTime) { this.lastUsedTime = lastUsedTime; }
}
