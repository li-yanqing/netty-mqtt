package nl.jk5.mqtt;

import java.net.Socket;
import java.net.URI;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import java.util.Vector;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

import io.netty.handler.ssl.util.SimpleTrustManagerFactory;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;

/**
 * TrustManager that verifies server certs using OCSP
 */
public class OCSPTrustManagerFactory extends SimpleTrustManagerFactory {
    private static final InternalLogger         logger         = InternalLoggerFactory
            .getInstance(OCSPTrustManagerFactory.class);

    public static final OCSPTrustManagerFactory INSTANCE       = new OCSPTrustManagerFactory();

    private static final TrustManager           tm             = new InnerX509TrustManager();

    public static final AtomicBoolean           inited         = new AtomicBoolean(false);

    private static String                       ocspServerString;

    private static X509Certificate              ocspRootCACert = null;

    private OCSPTrustManagerFactory() {
    }

    public static String getOcspServerString() {
        return ocspServerString;
    }

    public static X509Certificate getOcspRootCACert() {
        return ocspRootCACert;
    }

    public static void setOcspRootCACert(X509Certificate ocspRootCACert) {
        OCSPTrustManagerFactory.ocspRootCACert = ocspRootCACert;
    }

    public static void setOcspServerString(String ocspServerString) {
        OCSPTrustManagerFactory.ocspServerString = ocspServerString;
    }

    protected void engineInit(KeyStore keyStore) throws Exception {
        logger.debug("KeyStore is: {}", keyStore.toString());
    }

    protected void engineInit(ManagerFactoryParameters managerFactoryParameters) throws Exception {
    }

    protected TrustManager[] engineGetTrustManagers() {
        return new TrustManager[] { tm };
    }

    private static class InnerX509TrustManager extends X509ExtendedTrustManager {

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

          //TODO  test again!
            try {
                CertPath cp = null;
                Vector certs = new Vector();
                URI ocspServer = null;

                // load the cert to be checked
                certs.add(chain[0]);

                // handle location of OCSP server
                ocspServer = new URI(ocspServerString);
                logger.debug("Using the OCSP server");
                logger.debug("to check the revocation status of: " + certs.elementAt(0));

                // init cert path
                CertificateFactory cf = CertificateFactory.getInstance("X509");
                cp = (CertPath) cf.generateCertPath(certs);

                // load the root CA cert for the OCSP server cert
                X509Certificate rootCACert = ocspRootCACert;

                // init trusted certs
                TrustAnchor ta = new TrustAnchor(rootCACert, null);
                Set trustedCertsSet = new HashSet();
                trustedCertsSet.add(ta);

                // init PKIX parameters
                PKIXParameters params = null;

                params = new PKIXParameters(trustedCertsSet);
                // params.addCertStore(store);

                // enable OCSP
                logger.debug("Enable ocsp");
                Security.setProperty("ocsp.enable", "true");

                if (ocspServer != null) {
                    Security.setProperty("ocsp.responderURL", ocspServerString);
                }

                // perform validation
                CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
                PKIXCertPathValidatorResult cpv_result = (PKIXCertPathValidatorResult) cpv.validate(cp, params);
                X509Certificate trustedCert = (X509Certificate) cpv_result.getTrustAnchor().getTrustedCert();

                if (trustedCert == null) {
                    logger.debug("Trsuted Cert = NULL");
                } else {
                    logger.debug("Trusted CA DN = " + trustedCert.getSubjectDN());
                }
            } catch (CertPathValidatorException e) {
                // TODO re-throw exception
                e.printStackTrace();
            } catch (Exception e) {
                // TODO re-throw exception
                e.printStackTrace();
            }

        }

    }

}