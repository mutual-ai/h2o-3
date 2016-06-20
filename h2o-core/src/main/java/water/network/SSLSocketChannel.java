package water.network;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;

/**
 * This class is based on:
 * <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html">Oracle's JSSE guide.</a>
 * <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/samples/sslengine/SSLEngineSimpleDemo.java">Oracle's SSLEngine demo.</a>
 *
 * It's a simple wrapper around SocketChannels which enables SSL/TLS
 * communication using {@link javax.net.ssl.SSLEngine}.
 */
public class SSLSocketChannel implements ByteChannel {

    // Empty buffer used during SSL/TLS handshake
    private static ByteBuffer emptyBuffer = ByteBuffer.allocate(0);

    // Buffers holding encrypted data
    private ByteBuffer netInBuffer;
    private ByteBuffer netOutBuffer;

    // Buffers holding decrypted data
    // Probably can use only 1 buffer for both with some flag
    private ByteBuffer myAppData;
    private ByteBuffer peerAppData;

    private ByteChannel channel = null;
    private SSLEngine sslEngine = null;

    private boolean closing = false;
    private boolean closed = false;

    public SSLSocketChannel(ByteChannel channel, SSLEngine sslEngine) throws IOException {
        this.channel = channel;
        this.sslEngine = sslEngine;

        sslEngine.setEnableSessionCreation(true);
        SSLSession session = sslEngine.getSession();
        prepareBuffers(session);

        handshake();
    }

    @Override
    public boolean isOpen() {
        return channel.isOpen();
    }

    @Override
    public void close() throws IOException {
        closing = true;
        sslEngine.closeOutbound();
        sslEngine.getSession().invalidate();
        netOutBuffer.clear();
        myAppData.clear();

        while (!sslEngine.isOutboundDone()) {
            sslEngine.wrap(myAppData, netOutBuffer);

            while(netOutBuffer.hasRemaining()) {
                channel.write(netOutBuffer);
                netOutBuffer.compact();
            }
        }

        channel.close();
        closed = true;
    }

    private void prepareBuffers(SSLSession session) {
        int appBufferSize = session.getApplicationBufferSize();
        // Less is not more. More is more. Bigger than the app buffer size so successful unwraps() don't cause BUFFER_OVERFLOW
        myAppData = ByteBuffer.allocate(appBufferSize + 64);
        peerAppData = ByteBuffer.allocate(appBufferSize + 64);

        int netBufferSize = session.getPacketBufferSize();

        netInBuffer = ByteBuffer.allocate(netBufferSize);
        netOutBuffer = ByteBuffer.allocate(netBufferSize);
    }

    // -----------------------------------------------------------
    // HANDSHAKE
    // -----------------------------------------------------------

    private void handshake() throws IOException {
        sslEngine.beginHandshake();
        SSLEngineResult.HandshakeStatus hs = sslEngine.getHandshakeStatus();

        while(hs != SSLEngineResult.HandshakeStatus.FINISHED &&
                hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            switch(hs){
                case NEED_WRAP : {
                    myAppData.clear();
                    channel.write(wrap(emptyBuffer));
                }
                case NEED_UNWRAP:
                    netInBuffer.clear();
                    if(channel.read(netInBuffer) > 1) {
                        unwrap(peerAppData);
                    }
                    break;
                // SSL needs to perform some delegating tasks before it can continue.
                // Those tasks will be run in the same thread and can be blocking.
                case NEED_TASK :
                    hs = tasks();
                    break;
            }
        }
        resetBuffers();
    }

    private void resetBuffers() {
        myAppData.clear();
        peerAppData.clear();
        netInBuffer.clear();
        netOutBuffer.clear();
    }

    // -----------------------------------------------------------
    // READ AND WRITE
    // -----------------------------------------------------------

    @Override
    public int read(ByteBuffer dst) throws IOException {
        if (closing || closed) return -1;

        int read = channel.read(netInBuffer);

        if (read == -1 || read == 0) {
            return read;
        } else {
            return unwrap(dst);
        }
    }

    private synchronized int unwrap(ByteBuffer dst) throws IOException {
        int read = 0;
        SSLEngineResult unwrapResult;
        peerAppData.clear();

        while(netInBuffer.hasRemaining()) {
            netInBuffer.flip();

            unwrapResult = sslEngine.unwrap(netInBuffer, dst);
            netInBuffer.compact();

            switch (unwrapResult.getStatus()) {
                case OK: {
                    read += unwrapResult.bytesProduced();

                    if (unwrapResult.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                        tasks();
                    }
                    break;
                }
                case BUFFER_OVERFLOW: {
                    if (sslEngine.getSession().getApplicationBufferSize() > peerAppData.capacity()) {
                        int appSize = sslEngine.getSession().getApplicationBufferSize();
                        ByteBuffer b = ByteBuffer.allocate(appSize + peerAppData.position());
                        peerAppData.flip();
                        b.put(peerAppData);
                        peerAppData = b;
                    } else if(peerAppData.hasRemaining()) {
                        peerAppData.compact();
                    } else {
                        peerAppData.clear();
                    }
                    break;
                }
                case BUFFER_UNDERFLOW: {
                    if (sslEngine.getSession().getPacketBufferSize() > netInBuffer.capacity()) {
                        int netSize = sslEngine.getSession().getPacketBufferSize();
                        if (netSize > netInBuffer.capacity()) {
                            ByteBuffer b = ByteBuffer.allocate(netSize);
                            netInBuffer.flip();
                            b.put(netInBuffer);
                            netInBuffer = b;
                        }
                    } else if(netInBuffer.hasRemaining()) {
                        netInBuffer.compact();
                    } else {
                        netInBuffer.clear();
                    }
                    break;
                }
                default:
                    throw new IOException("Failed to SSL unwrap with status " + unwrapResult.getStatus());
            }
        }

        return read;
    }

    @Override
    public int write(ByteBuffer src) throws IOException {
        if(closing || closed) {
            throw new IOException("Cannot perform socket write, the socket is closed (or being closed).");
        }

        if(!flush(netOutBuffer)) {
            return 0;
        }

        return channel.write(wrap(src));
    }

    private synchronized ByteBuffer wrap(ByteBuffer src) throws IOException {
        netOutBuffer.clear();
        sslEngine.wrap(src, netOutBuffer);
        netOutBuffer.flip();
        return netOutBuffer;
    }

    private boolean flush(ByteBuffer buf) throws IOException {
        int remaining = buf.remaining();
        if ( remaining > 0 ) {
            int written = channel.write(buf);
            return written >= remaining;
        }else {
            return true;
        }
    }

    // -----------------------------------------------------------
    // MISC
    // -----------------------------------------------------------

    private SSLEngineResult.HandshakeStatus tasks() {
        Runnable r;
        while ( (r = sslEngine.getDelegatedTask()) != null) {
            r.run();
        }
        return sslEngine.getHandshakeStatus();
    }
}
