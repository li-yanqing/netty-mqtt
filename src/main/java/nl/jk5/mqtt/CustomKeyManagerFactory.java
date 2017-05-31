package nl.jk5.mqtt;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;

public class CustomKeyManagerFactory extends KeyManagerFactorySpi {

//    private KeyManager km = new InnerKeyManager();

    @Override
    protected KeyManager[] engineGetKeyManagers() {
        // TODO Auto-generated method stub
//        return new KeyManager[]{km};
        return null;
    }

    @Override
    protected void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
        // TODO Auto-generated method stub
        
    }

    @Override
    protected void engineInit(KeyStore ks, char[] password)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        // TODO Auto-generated method stub
        
    }

    
//    private class InnerKeyManager implements 
    


}
