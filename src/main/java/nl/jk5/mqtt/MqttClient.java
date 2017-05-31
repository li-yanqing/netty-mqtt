package nl.jk5.mqtt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.ImmutableSet;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.mqtt.MqttDecoder;
import io.netty.handler.codec.mqtt.MqttEncoder;
import io.netty.handler.codec.mqtt.MqttFixedHeader;
import io.netty.handler.codec.mqtt.MqttMessage;
import io.netty.handler.codec.mqtt.MqttMessageIdVariableHeader;
import io.netty.handler.codec.mqtt.MqttMessageType;
import io.netty.handler.codec.mqtt.MqttPublishMessage;
import io.netty.handler.codec.mqtt.MqttPublishVariableHeader;
import io.netty.handler.codec.mqtt.MqttQoS;
import io.netty.handler.codec.mqtt.MqttSubscribeMessage;
import io.netty.handler.codec.mqtt.MqttSubscribePayload;
import io.netty.handler.codec.mqtt.MqttTopicSubscription;
import io.netty.handler.codec.mqtt.MqttUnsubscribeMessage;
import io.netty.handler.codec.mqtt.MqttUnsubscribePayload;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.timeout.IdleStateHandler;
import io.netty.util.collection.IntObjectHashMap;
import io.netty.util.concurrent.DefaultPromise;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.Promise;

/**
 * Represents an MqttClient connected to a single MQTT server. Will try to keep the connection going at all times
 */
@SuppressWarnings({ "WeakerAccess", "unused" })
public final class MqttClient {

    private final Set<String>                                 serverSubscribtions          = new HashSet<>();

    private final IntObjectHashMap<MqttPendingUnsubscribtion> pendingServerUnsubscribes    = new IntObjectHashMap<>();

    private final IntObjectHashMap<MqttIncomingQos2Publish>   qos2PendingIncomingPublishes = new IntObjectHashMap<>();

    private final IntObjectHashMap<MqttPendingPublish>        pendingPublishes             = new IntObjectHashMap<>();

    private final HashMultimap<String, MqttSubscribtion>      subscriptions                = HashMultimap.create();

    private final IntObjectHashMap<MqttPendingSubscribtion>   pendingSubscribtions         = new IntObjectHashMap<>();

    private final Set<String>                                 pendingSubscribeTopics       = new HashSet<>();

    private final HashMultimap<MqttHandler, MqttSubscribtion> handlerToSubscribtion        = HashMultimap.create();

    private final AtomicInteger                               nextMessageId                = new AtomicInteger(1);

    private final MqttClientConfig                            clientConfig;

    private EventLoopGroup                                    eventLoop;

    private Channel                                           channel;

    private MqttConnectionHandler                             connectionHandler            = new MqttConnectionHandler() {
                                                                                               public void onConnected() {
                                                                                               }

                                                                                               public void onDisConnected() {
                                                                                               }

                                                                                               public void onConnectFailed() {
                                                                                               }
                                                                                           };

    /**
     * Construct the MqttClient with default config
     */
    public MqttClient() {
        this.clientConfig = new MqttClientConfig();
    }

    /**
     * Construct the MqttClient with additional config. This config can also be changed using the
     * {@link #getClientConfig()} function
     *
     * @param clientConfig
     *            The config object to use while looking for settings
     */
    public MqttClient(MqttClientConfig clientConfig) {
        this.clientConfig = clientConfig;
    }

    /**
     * Connect to the specified hostname/ip. By default uses port 1883. If you want to change the port number, see
     * {@link #connect(String, int)}
     *
     * @param host
     *            The ip address or host to connect to
     * @return A future which will be completed when the connection is opened and we received an CONNACK
     */
    public Future<MqttConnectResult> connect(String host) {
        return connect(host, 1883);
    }

    /**
     * Connect to the specified hostname/ip using the specified port
     *
     * @param host
     *            The ip address or host to connect to
     * @param port
     *            The tcp port to connect to
     * @return A future which will be completed when the connection is opened and we received an CONNACK
     */
    public Future<MqttConnectResult> connect(String host, int port) {
        if (this.eventLoop == null) {
            this.eventLoop = new NioEventLoopGroup();
        }
        Promise<MqttConnectResult> connectFuture = new DefaultPromise<>(this.eventLoop.next());
        Bootstrap bootstrap = new Bootstrap();
        bootstrap.group(this.eventLoop);
        bootstrap.channel(clientConfig.getChannelClass());
        bootstrap.option(ChannelOption.ALLOCATOR, ByteBufAllocator.DEFAULT);
        bootstrap.option(ChannelOption.SO_KEEPALIVE, true);
        bootstrap.option(ChannelOption.CONNECT_TIMEOUT_MILLIS, this.clientConfig.getTimeoutSeconds() * 1000);
        bootstrap.handler(new LoggingHandler(LogLevel.INFO));

        bootstrap.remoteAddress(host, port);
        bootstrap.handler(new MqttChannelInitializer(connectFuture));
        ChannelFuture future = bootstrap.connect();
        future.addListener((ChannelFutureListener) f -> {
            if (!f.isSuccess()) {
                if (!connectFuture.isDone()) {
                    connectFuture.setFailure(f.cause());
                }
            } else {
                channel = f.channel();
            }
        });

        return connectFuture;
    }

    public ChannelFuture disconnect() {
        MqttFixedHeader header = new MqttFixedHeader(MqttMessageType.DISCONNECT, false, MqttQoS.AT_MOST_ONCE, false, 0);
        return channel.writeAndFlush(new MqttMessage(header)).addListener(ChannelFutureListener.CLOSE);
    }

    /**
     * Retrieve the netty {@link EventLoopGroup} we are using
     * 
     * @return The netty {@link EventLoopGroup} we use for the connection
     */
    public EventLoopGroup getEventLoop() {
        return eventLoop;
    }

    /**
     * By default we use the netty {@link NioEventLoopGroup}. If you change the EventLoopGroup to another type, make
     * sure to change the {@link Channel} class using {@link MqttClientConfig#setChannelClass(Class)} If you want to
     * force the MqttClient to use another {@link EventLoopGroup}, call this function before calling
     * {@link #connect(String, int)}
     *
     * @param eventLoop
     *            The new eventloop to use
     */
    public void setEventLoop(EventLoopGroup eventLoop) {
        this.eventLoop = eventLoop;
    }

    /**
     * Subscribe on the given topic. When a message is received, MqttClient will invoke the
     * {@link MqttHandler#onMessage(String, ByteBuf)} function of the given handler
     *
     * @param topic
     *            The topic filter to subscribe to
     * @param handler
     *            The handler to invoke when we receive a message
     * @return A future which will be completed when the server acknowledges our subscribe request
     */
    public Future<Void> on(String topic, MqttHandler handler) {
        return on(topic, handler, MqttQoS.AT_MOST_ONCE);
    }

    /**
     * Subscribe on the given topic, with the given qos. When a message is received, MqttClient will invoke the
     * {@link MqttHandler#onMessage(String, ByteBuf)} function of the given handler
     *
     * @param topic
     *            The topic filter to subscribe to
     * @param handler
     *            The handler to invoke when we receive a message
     * @param qos
     *            The qos to request to the server
     * @return A future which will be completed when the server acknowledges our subscribe request
     */
    public Future<Void> on(String topic, MqttHandler handler, MqttQoS qos) {
        return createSubscribtion(topic, handler, false, qos);
    }

    /**
     * Subscribe on the given topic. When a message is received, MqttClient will invoke the
     * {@link MqttHandler#onMessage(String, ByteBuf)} function of the given handler This subscribtion is only once. If
     * the MqttClient has received 1 message, the subscribtion will be removed
     *
     * @param topic
     *            The topic filter to subscribe to
     * @param handler
     *            The handler to invoke when we receive a message
     * @return A future which will be completed when the server acknowledges our subscribe request
     */
    public Future<Void> once(String topic, MqttHandler handler) {
        return once(topic, handler, MqttQoS.AT_MOST_ONCE);
    }

    /**
     * Subscribe on the given topic, with the given qos. When a message is received, MqttClient will invoke the
     * {@link MqttHandler#onMessage(String, ByteBuf)} function of the given handler This subscribtion is only once. If
     * the MqttClient has received 1 message, the subscribtion will be removed
     *
     * @param topic
     *            The topic filter to subscribe to
     * @param handler
     *            The handler to invoke when we receive a message
     * @param qos
     *            The qos to request to the server
     * @return A future which will be completed when the server acknowledges our subscribe request
     */
    public Future<Void> once(String topic, MqttHandler handler, MqttQoS qos) {
        return createSubscribtion(topic, handler, true, qos);
    }

    /**
     * Remove the subscribtion for the given topic and handler If you want to unsubscribe from all handlers known for
     * this topic, use {@link #off(String)}
     *
     * @param topic
     *            The topic to unsubscribe for
     * @param handler
     *            The handler to unsubscribe
     * @return A future which will be completed when the server acknowledges our unsubscribe request
     */
    public Future<Void> off(String topic, MqttHandler handler) {
        Promise<Void> future = new DefaultPromise<>(this.eventLoop.next());
        for (MqttSubscribtion subscribtion : this.handlerToSubscribtion.get(handler)) {
            this.subscriptions.remove(topic, subscribtion);
        }
        this.handlerToSubscribtion.removeAll(handler);
        this.checkSubscribtions(topic, future);
        return future;
    }

    /**
     * Remove all subscribtions for the given topic. If you want to specify which handler to unsubscribe, use
     * {@link #off(String, MqttHandler)}
     *
     * @param topic
     *            The topic to unsubscribe for
     * @return A future which will be completed when the server acknowledges our unsubscribe request
     */
    public Future<Void> off(String topic) {
        Promise<Void> future = new DefaultPromise<>(this.eventLoop.next());
        ImmutableSet<MqttSubscribtion> subscribtions = ImmutableSet.copyOf(this.subscriptions.get(topic));
        for (MqttSubscribtion subscribtion : subscribtions) {
            for (MqttSubscribtion handSub : this.handlerToSubscribtion.get(subscribtion.getHandler())) {
                this.subscriptions.remove(topic, handSub);
            }
            this.handlerToSubscribtion.remove(subscribtion.getHandler(), subscribtion);
        }
        this.checkSubscribtions(topic, future);
        return future;
    }

    /**
     * Publish a message to the given payload
     * 
     * @param topic
     *            The topic to publish to
     * @param payload
     *            The payload to send
     * @return A future which will be completed when the message is sent out of the MqttClient
     */
    public Future<Void> publish(String topic, ByteBuf payload) {
        return publish(topic, payload, MqttQoS.AT_MOST_ONCE, false);
    }

    /**
     * Publish a message to the given payload, using the given qos
     * 
     * @param topic
     *            The topic to publish to
     * @param payload
     *            The payload to send
     * @param qos
     *            The qos to use while publishing
     * @return A future which will be completed when the message is delivered to the server
     */
    public Future<Void> publish(String topic, ByteBuf payload, MqttQoS qos) {
        return publish(topic, payload, qos, false);
    }

    /**
     * Publish a message to the given payload, using optional retain
     * 
     * @param topic
     *            The topic to publish to
     * @param payload
     *            The payload to send
     * @param retain
     *            true if you want to retain the message on the server, false otherwise
     * @return A future which will be completed when the message is sent out of the MqttClient
     */
    public Future<Void> publish(String topic, ByteBuf payload, boolean retain) {
        return publish(topic, payload, MqttQoS.AT_MOST_ONCE, retain);
    }

    /**
     * Publish a message to the given payload, using the given qos and optional retain
     * 
     * @param topic
     *            The topic to publish to
     * @param payload
     *            The payload to send
     * @param qos
     *            The qos to use while publishing
     * @param retain
     *            true if you want to retain the message on the server, false otherwise
     * @return A future which will be completed when the message is delivered to the server
     */
    public Future<Void> publish(String topic, ByteBuf payload, MqttQoS qos, boolean retain) {
        Promise<Void> future = new DefaultPromise<>(this.eventLoop.next());
        MqttFixedHeader fixedHeader = new MqttFixedHeader(MqttMessageType.PUBLISH, false, qos, retain, 0);
        MqttPublishVariableHeader variableHeader = new MqttPublishVariableHeader(topic, getNewMessageId().messageId());
        MqttPublishMessage message = new MqttPublishMessage(fixedHeader, variableHeader, payload);

        MqttPendingPublish pendingPublish = new MqttPendingPublish(variableHeader.messageId(), future, payload.retain(),
                message, qos);

        ChannelFuture pfuture = this.sendAndFlushPacket(message);

        pendingPublish.setSent(pfuture != null);

        if (pendingPublish.isSent() && pendingPublish.getQos() == MqttQoS.AT_MOST_ONCE) {
            pfuture.addListener((ChannelFutureListener) f -> {
                if (f.isSuccess()) {
                    pendingPublish.getFuture().setSuccess(null); // We don't get an ACK for QOS 0
                }
            });
        } else if (pendingPublish.isSent()) {
            this.pendingPublishes.put(pendingPublish.getMessageId(), pendingPublish);
            pendingPublish.startPublishRetransmissionTimer(this.eventLoop.next(), this::sendAndFlushPacket);
        }

        return future;
    }

    /**
     * Retrieve the MqttClient configuration
     * 
     * @return The {@link MqttClientConfig} instance we use
     */
    public MqttClientConfig getClientConfig() {
        return clientConfig;
    }

    ///////////////////////////////////////////// PRIVATE API /////////////////////////////////////////////

    ChannelFuture sendAndFlushPacket(Object message) {
        if (this.channel == null) {
            return null;
        }
        if (this.channel.isActive()) {
            return this.channel.writeAndFlush(message);
        }
        connectionHandler.onDisConnected();
        return this.channel.newFailedFuture(new RuntimeException("Channel is closed"));
    }

    private MqttMessageIdVariableHeader getNewMessageId() {
        this.nextMessageId.compareAndSet(0xffff, 1);
        return MqttMessageIdVariableHeader.from(this.nextMessageId.getAndIncrement());
    }

    private Future<Void> createSubscribtion(String topic, MqttHandler handler, boolean once, MqttQoS qos) {
        if (this.pendingSubscribeTopics.contains(topic)) {
            Optional<Map.Entry<Integer, MqttPendingSubscribtion>> subscribtionEntry = this.pendingSubscribtions
                    .entrySet().stream().filter((e) -> e.getValue().getTopic().equals(topic)).findAny();
            if (subscribtionEntry.isPresent()) {
                subscribtionEntry.get().getValue().addHandler(handler, once);
                return subscribtionEntry.get().getValue().getFuture();
            }
        }
        if (this.serverSubscribtions.contains(topic)) {
            MqttSubscribtion subscribtion = new MqttSubscribtion(topic, handler, once);
            this.subscriptions.put(topic, subscribtion);
            this.handlerToSubscribtion.put(handler, subscribtion);
            return this.channel.newSucceededFuture();
        }

        Promise<Void> future = new DefaultPromise<>(this.eventLoop.next());
        MqttFixedHeader fixedHeader = new MqttFixedHeader(MqttMessageType.SUBSCRIBE, false, MqttQoS.AT_LEAST_ONCE,
                false, 0);
        MqttTopicSubscription subscription = new MqttTopicSubscription(topic, qos);
        MqttMessageIdVariableHeader variableHeader = getNewMessageId();
        MqttSubscribePayload payload = new MqttSubscribePayload(Collections.singletonList(subscription));
        MqttSubscribeMessage message = new MqttSubscribeMessage(fixedHeader, variableHeader, payload);

        final MqttPendingSubscribtion pendingSubscribtion = new MqttPendingSubscribtion(future, topic, message);
        pendingSubscribtion.addHandler(handler, once);
        this.pendingSubscribtions.put(variableHeader.messageId(), pendingSubscribtion);
        this.pendingSubscribeTopics.add(topic);
        pendingSubscribtion.setSent(this.sendAndFlushPacket(message) != null); // If not sent, we will send it when the
                                                                               // connection is opened

        pendingSubscribtion.startRetransmitTimer(this.eventLoop.next(), this::sendAndFlushPacket);

        return future;
    }

    private void checkSubscribtions(String topic, Promise<Void> promise) {
        if (!(this.subscriptions.containsKey(topic) && this.subscriptions.get(topic).size() != 0)
                && this.serverSubscribtions.contains(topic)) {
            MqttFixedHeader fixedHeader = new MqttFixedHeader(MqttMessageType.UNSUBSCRIBE, false, MqttQoS.AT_LEAST_ONCE,
                    false, 0);
            MqttMessageIdVariableHeader variableHeader = getNewMessageId();
            MqttUnsubscribePayload payload = new MqttUnsubscribePayload(Collections.singletonList(topic));
            MqttUnsubscribeMessage message = new MqttUnsubscribeMessage(fixedHeader, variableHeader, payload);

            MqttPendingUnsubscribtion pendingUnsubscribtion = new MqttPendingUnsubscribtion(promise, topic, message);
            this.pendingServerUnsubscribes.put(variableHeader.messageId(), pendingUnsubscribtion);
            pendingUnsubscribtion.startRetransmissionTimer(this.eventLoop.next(), this::sendAndFlushPacket);

            this.sendAndFlushPacket(message);
        } else {
            promise.setSuccess(null);
        }
    }

    IntObjectHashMap<MqttPendingSubscribtion> getPendingSubscribtions() {
        return pendingSubscribtions;
    }

    HashMultimap<String, MqttSubscribtion> getSubscriptions() {
        return subscriptions;
    }

    Set<String> getPendingSubscribeTopics() {
        return pendingSubscribeTopics;
    }

    HashMultimap<MqttHandler, MqttSubscribtion> getHandlerToSubscribtion() {
        return handlerToSubscribtion;
    }

    Set<String> getServerSubscribtions() {
        return serverSubscribtions;
    }

    IntObjectHashMap<MqttPendingUnsubscribtion> getPendingServerUnsubscribes() {
        return pendingServerUnsubscribes;
    }

    IntObjectHashMap<MqttPendingPublish> getPendingPublishes() {
        return pendingPublishes;
    }

    IntObjectHashMap<MqttIncomingQos2Publish> getQos2PendingIncomingPublishes() {
        return qos2PendingIncomingPublishes;
    }

    public MqttConnectionHandler getConnectionHandler() {
        return connectionHandler;
    }

    public void setConnectionHandler(MqttConnectionHandler connectionHandler) {
        this.connectionHandler = connectionHandler;
    }

    private class MqttChannelInitializer extends ChannelInitializer<SocketChannel> {

        private final Promise<MqttConnectResult> connectFuture;

        MqttChannelInitializer(Promise<MqttConnectResult> connectFuture) {
            this.connectFuture = connectFuture;
        }

        @Override
        protected void initChannel(SocketChannel ch) throws Exception {
            if (MqttClient.this.clientConfig.isUseTLS()) {
                SslContext context = SslContextBuilder.forClient().keyManager(createKeyManager())
                        .trustManager(createTrustManager()).build();
                ch.pipeline().addLast("ssl", context.newHandler(ch.alloc()));
            }

            ch.pipeline().addLast("mqttDecoder", new MqttDecoder());
            ch.pipeline().addLast("mqttEncoder", MqttEncoder.INSTANCE);
            ch.pipeline().addLast("idleStateHandler",
                    new IdleStateHandler(MqttClient.this.clientConfig.getTimeoutSeconds(),
                            MqttClient.this.clientConfig.getTimeoutSeconds(), 0));
            ch.pipeline().addLast("mqttPingHandler",
                    new MqttPingHandler(MqttClient.this.clientConfig.getTimeoutSeconds()));
            ch.pipeline().addLast("mqttHandler", new MqttChannelHandler(MqttClient.this, connectFuture));

        }

        private TrustManagerFactory createTrustManager() {
            if (clientConfig.isUseOCSP()) {
                System.setProperty("com.sun.security.enableCRLDP", "true");
                System.setProperty("com.sun.net.ssl.checkRevocation", "true");
                Security.setProperty("ocsp.enable", "true");
                Security.setProperty("ocsp.responderURL", clientConfig.getOcspResponderURL());

                OCSPTrustManagerFactory ocsp = OCSPTrustManagerFactory.INSTANCE;
                while (!OCSPTrustManagerFactory.inited.get()
                        && OCSPTrustManagerFactory.inited.compareAndSet(false, true)) {
                    OCSPTrustManagerFactory.setOcspServerString(clientConfig.getOcspResponderURL());
                    OCSPTrustManagerFactory.setOcspRootCACert(getCertFromFile(clientConfig.getOcspRootCA()));
                }

                return ocsp;
            }
            return TrustAllManagerFactory.INSTANCE;

        }

        private KeyManagerFactory createKeyManager() {
            KeyManagerFactory kmf = null;
            String privateKeyEntryPassword = "password";
            try {
                KeyStore ks = KeyStore.getInstance("JKS");
                ks.load(null, null);

                File clientKeyFile = clientConfig.getClientKeyFile();
                File clientCertFile = clientConfig.getClientCertFile();
                if (clientKeyFile == null || clientCertFile == null || !clientKeyFile.exists()
                        || !clientKeyFile.isFile() || !clientCertFile.exists() || !clientCertFile.isFile()) {
                    throw new FileNotFoundException("Client's key and cert files are missing."
                            + (clientKeyFile == null ? "" : "\n" + clientKeyFile.getAbsolutePath())
                            + (clientCertFile == null ? "" : "\n" + clientCertFile.getAbsolutePath()));
                }

                Certificate[] chain = { getCertFromFile(clientCertFile) };
                KeyFactory rSAKeyFactory = KeyFactory.getInstance("RSA");
                PrivateKey privateKey = new PrivateKeyReader(clientKeyFile.getAbsolutePath()).getPrivateKey();
                ks.setEntry("client", new KeyStore.PrivateKeyEntry(privateKey, chain),
                        new KeyStore.PasswordProtection(privateKeyEntryPassword.toCharArray()));

                kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(ks, privateKeyEntryPassword.toCharArray());
            } catch (Throwable e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
            return kmf;
        }

    }

    /*
     * Read a certificate from the specified filepath.
     */
    private static X509Certificate getCertFromFile(String path) {
        return getCertFromFile(new File(path));
    }

    private static X509Certificate getCertFromFile(File certFile) {
        X509Certificate cert = null;
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(certFile);
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            cert = (X509Certificate) cf.generateCertificate(fis);
        } catch (Exception e) {
            throw new RuntimeException("Can't construct X509 Certificate. " + e.getMessage());
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return cert;

    }

}
