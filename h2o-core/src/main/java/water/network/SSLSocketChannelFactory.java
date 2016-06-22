package water.network;

import water.H2O;
import water.util.Log;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.channels.ByteChannel;
import java.nio.channels.SocketChannel;
import java.security.*;
import java.security.cert.CertificateException;

public class SSLSocketChannelFactory {

    private SSLContext sslContext = null;

    public SSLSocketChannelFactory() throws SSLContextException {
        try {
            this.sslContext = SSLContext.getInstance(H2O.ARGS.h2o_ssl_protocol);
            this.sslContext.init(keyManager(), trustManager(), null);
        } catch (NoSuchAlgorithmException | IOException | UnrecoverableKeyException | KeyStoreException | KeyManagementException | CertificateException e) {
            Log.err("Failed to initialized SSL context.", e);
            throw new SSLContextException("Failed to initialized SSL context.", e);
        }
    }

    private TrustManager[] trustManager() throws
            KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore ksTrust = KeyStore.getInstance("JKS");

        assert H2O.ARGS.h2o_ssl_jts != null && H2O.ARGS.h2o_ssl_jts_password != null;

        ksTrust.load(
                new FileInputStream(H2O.ARGS.h2o_ssl_jts),
                H2O.ARGS.h2o_ssl_jts_password.toCharArray()
        );
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ksTrust);
        return tmf.getTrustManagers();
    }

    private KeyManager[] keyManager() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore ksKeys = KeyStore.getInstance("JKS");

        assert H2O.ARGS.h2o_ssl_jks_internal != null && H2O.ARGS.h2o_ssl_jks_password != null;

        ksKeys.load(new FileInputStream(H2O.ARGS.h2o_ssl_jks_internal),
                H2O.ARGS.h2o_ssl_jks_password.toCharArray()
        );
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ksKeys, H2O.ARGS.h2o_ssl_jks_password.toCharArray());
        return kmf.getKeyManagers();
    }

    public ByteChannel wrapClientChannel(
            SocketChannel channel,
            String host,
            int port) throws IOException {
        SSLEngine sslEngine = sslContext.createSSLEngine(host, port);
        sslEngine.setUseClientMode(false);
        if(null != H2O.ARGS.h2o_ssl_enabled_algorithms) {
            sslEngine.setEnabledCipherSuites(H2O.ARGS.h2o_ssl_enabled_algorithms);
        }
        return new SSLSocketChannel(channel, sslEngine);
    }

    public ByteChannel wrapServerChannel(SocketChannel channel) throws IOException {
        SSLEngine sslEngine = sslContext.createSSLEngine();
        sslEngine.setUseClientMode(true);
        if(null != H2O.ARGS.h2o_ssl_enabled_algorithms) {
            sslEngine.setEnabledCipherSuites(H2O.ARGS.h2o_ssl_enabled_algorithms);
        }
        return new SSLSocketChannel(channel, sslEngine);
    }
}
