package nl.jk5.mqtt;

import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

import io.netty.handler.ssl.util.SimpleTrustManagerFactory;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;

public class TrustAllManagerFactory extends SimpleTrustManagerFactory {
    private static final InternalLogger        logger   = InternalLoggerFactory
            .getInstance(TrustAllManagerFactory.class);

    public static final TrustAllManagerFactory INSTANCE = new TrustAllManagerFactory();

    private static final TrustManager          tm       = new TrustAllX509TrustManager();

    private TrustAllManagerFactory() {
    }

    protected void engineInit(KeyStore keyStore) throws Exception {
    }

    protected void engineInit(ManagerFactoryParameters managerFactoryParameters) throws Exception {
    }

    protected TrustManager[] engineGetTrustManagers() {
        return new TrustManager[] { tm };
    }

    private static class TrustAllX509TrustManager extends X509ExtendedTrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {

        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {

        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
                throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
                throws CertificateException {

        }

    }

}