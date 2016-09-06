package nl.jk5.mqtt;

public interface MqttConnectionHandler {

    void onConnected();

    void onDisConnected();

    void onConnectFailed();
}
