package water.network;

import water.H2O;

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
            this.sslContext = SSLContext.getDefault();
            this.sslContext.init(keyManager(), trustManager(), null);
        } catch (NoSuchAlgorithmException | IOException | UnrecoverableKeyException | KeyStoreException | KeyManagementException | CertificateException e) {
            // TODO log
            throw new SSLContextException("Failed to initialized SSL context.", e);
        }
    }

    private TrustManager[] trustManager() throws
            KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore ksTrust = KeyStore.getInstance("JKS");

        assert H2O.ARGS.h2o_ssl_trustStore != null && H2O.ARGS.h2o_ssl_trustStorePassword != null;

        ksTrust.load(
                new FileInputStream(H2O.ARGS.h2o_ssl_trustStore),
                H2O.ARGS.h2o_ssl_trustStorePassword.toCharArray()
        );
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ksTrust);
        return tmf.getTrustManagers();
    }

    private KeyManager[] keyManager() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore ksKeys = KeyStore.getInstance("JKS");

        assert H2O.ARGS.h2o_ssl_jks_internal != null && H2O.ARGS.h2o_ssl_keyStorePassword != null;

        ksKeys.load(new FileInputStream(H2O.ARGS.h2o_ssl_jks_internal),
                H2O.ARGS.h2o_ssl_keyStorePassword.toCharArray()
        );
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ksKeys, H2O.ARGS.h2o_ssl_keyStorePassword.toCharArray());
        return kmf.getKeyManagers();
    }

    public ByteChannel wrapClientChannel(
            SocketChannel channel,
            String host,
            int port) throws IOException {
        SSLEngine sslEngine = sslContext.createSSLEngine(host, port);
        sslEngine.setUseClientMode(false);
        return new SSLSocketChannel(channel, sslEngine);
    }

    public ByteChannel wrapServerChannel(SocketChannel channel) throws IOException {
        SSLEngine sslEngine = sslContext.createSSLEngine();
        sslEngine.setUseClientMode(true);
        return new SSLSocketChannel(channel, sslEngine);
    }
}
