package nl.jk5.mqtt;

import java.io.File;
import java.util.Random;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import io.netty.channel.Channel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.mqtt.MqttVersion;

@SuppressWarnings({ "WeakerAccess", "unused" })
public final class MqttClientConfig {

    private final String             randomClientId;

    private String                   clientId;

    private int                      timeoutSeconds  = 10;

    private MqttVersion              protocolVersion = MqttVersion.MQTT_3_1;

    @Nullable
    private String                   username        = null;

    @Nullable
    private String                   password        = null;

    private boolean                  cleanSession    = false;

    @Nullable
    private MqttLastWill             lastWill;

    private Class<? extends Channel> channelClass    = NioSocketChannel.class;

    private boolean                  useTLS          = false;

    private File                     clientKeyFile;

    private File                     clientCertFile;

    private File                     ocspRootCA;

    private boolean                  useOCSP         = false;

    private String                   ocspResponderURL;

    public MqttClientConfig() {
        Random random = new Random();
        String id = "netty-mqtt/";
        String[] options = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".split("");
        for (int i = 0; i < 8; i++) {
            id += options[random.nextInt(options.length)];
        }
        this.clientId = id;
        this.randomClientId = id;
    }

    @Nonnull
    public String getClientId() {
        return clientId;
    }

    public void setClientId(@Nullable String clientId) {
        if (clientId == null) {
            this.clientId = randomClientId;
        } else {
            this.clientId = clientId;
        }
    }

    public int getTimeoutSeconds() {
        return timeoutSeconds;
    }

    public void setTimeoutSeconds(int timeoutSeconds) {
        if (timeoutSeconds != -1 && timeoutSeconds <= 0) {
            throw new IllegalArgumentException("timeoutSeconds must be > 0 or -1");
        }
        this.timeoutSeconds = timeoutSeconds;
    }

    public MqttVersion getProtocolVersion() {
        return protocolVersion;
    }

    public void setProtocolVersion(MqttVersion protocolVersion) {
        if (protocolVersion == null) {
            throw new NullPointerException("protocolVersion");
        }
        this.protocolVersion = protocolVersion;
    }

    @Nullable
    public String getUsername() {
        return username;
    }

    public void setUsername(@Nullable String username) {
        this.username = username;
    }

    @Nullable
    public String getPassword() {
        return password;
    }

    public void setPassword(@Nullable String password) {
        this.password = password;
    }

    public boolean isCleanSession() {
        return cleanSession;
    }

    public void setCleanSession(boolean cleanSession) {
        this.cleanSession = cleanSession;
    }

    @Nullable
    public MqttLastWill getLastWill() {
        return lastWill;
    }

    public void setLastWill(@Nullable MqttLastWill lastWill) {
        this.lastWill = lastWill;
    }

    public Class<? extends Channel> getChannelClass() {
        return channelClass;
    }

    public void setChannelClass(Class<? extends Channel> channelClass) {
        this.channelClass = channelClass;
    }

    public boolean isUseTLS() {
        return useTLS;
    }

    public void setUseTLS(boolean useTLS) {
        this.useTLS = useTLS;
    }

    public File getClientKeyFile() {
        return clientKeyFile;
    }

    public void setClientKeyFile(File clientKeyFile) {
        this.clientKeyFile = clientKeyFile;
    }

    public File getClientCertFile() {
        return clientCertFile;
    }

    public void setClientCertFile(File clientCertFile) {
        this.clientCertFile = clientCertFile;
    }

    public boolean isUseOCSP() {
        return useOCSP;
    }

    public void setUseOCSP(boolean useOCSP) {
        this.useOCSP = useOCSP;
    }

    public String getOcspResponderURL() {
        return ocspResponderURL;
    }

    public void setOcspResponderURL(String ocspResponderURL) {
        this.ocspResponderURL = ocspResponderURL;
    }

    public File getOcspRootCA() {
        return ocspRootCA;
    }

    public void setOcspRootCA(File ocspRootCA) {
        this.ocspRootCA = ocspRootCA;
    }

}
