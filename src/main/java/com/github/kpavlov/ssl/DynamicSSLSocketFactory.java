/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Konstantin Pavlov
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.github.kpavlov.ssl;

import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.SSLContexts;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

public class DynamicSSLSocketFactory extends SSLSocketFactory {

    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(DynamicSSLSocketFactory.class);

    private final KeyStoreProvider keyStoreProvider;
    private final KeyPasswordProvider keyPasswordProvider;

    private final Map<String, SSLSocketFactory> sslSocketFactoryMap = new ConcurrentHashMap<String, SSLSocketFactory>() {
        @Override
        public SSLSocketFactory computeIfAbsent(String host, Function<? super String, ? extends SSLSocketFactory> mappingFunction) {
            try {
                final KeyStore keyStore = keyStoreProvider.getKeyStore(host);
                final KeyStore trustStore = keyStoreProvider.getTrustStore(host);
                final char[] keyPassword = keyPasswordProvider.getPassword(host);

                final SSLContextBuilder contextBuilder = SSLContexts.custom();
                if (keyStore != null) {
                    contextBuilder.loadKeyMaterial(keyStore, keyPassword);
                }
                if (trustStore != null) {
                    contextBuilder.loadTrustMaterial(trustStore);
                }

                SSLContext sslContext = contextBuilder
                        .useTLS()
                        .build();

                return sslContext.getSocketFactory();
            } catch (Exception e) {
                LOGGER.error("Unable to create SSLContext", e);
            }

            return null;
        }
    };

    public DynamicSSLSocketFactory(KeyStoreProvider keyStoreProvider, KeyPasswordProvider keyPasswordProvider) {
        this.keyPasswordProvider = keyPasswordProvider;
        this.keyStoreProvider = keyStoreProvider;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        throw new UnsupportedOperationException("Method is not implemented: com.github.kpavlov.ssl.DynamicSSLSocketFactory.getDefaultCipherSuites");
    }

    @Override
    public String[] getSupportedCipherSuites() {
        throw new UnsupportedOperationException("Method is not implemented: com.github.kpavlov.ssl.DynamicSSLSocketFactory.getSupportedCipherSuites");
    }

    /**
     * Returns a socket layered over an existing socket connected to the named host, at the given port.
     */
    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
        return getSslSocketFactory(host).createSocket(socket, host, port, autoClose);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return getSslSocketFactory(host).createSocket(host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        return getSslSocketFactory(host).createSocket(host, port, localHost, localPort);
    }

    @Override
    public Socket createSocket(InetAddress address, int port) throws IOException {
        return getSslSocketFactory(address.getHostName()).createSocket(address, port);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return getSslSocketFactory(address.getHostName()).createSocket(address, port, localAddress, localPort);
    }

    private SSLSocketFactory getSslSocketFactory(String host) {
        return sslSocketFactoryMap.get(host);
    }

}
