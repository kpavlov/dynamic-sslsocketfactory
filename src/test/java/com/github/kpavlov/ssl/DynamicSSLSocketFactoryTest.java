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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class DynamicSSLSocketFactoryTest {

    private static java.security.KeyStore testKeyStore;
    private static KeyStore testTrustStore;

    private DynamicSSLSocketFactory factory;
    @Mock
    private KeyStoreProvider keyStoreProvider;
    @Mock
    private KeyPasswordProvider passwordProvider;

    public static void beforeClass() throws KeyStoreException {
        testKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        testTrustStore = KeyStore.getInstance(KeyStore.getDefaultType());
    }

    @Before
    public void beforeMethod() {
        factory = new DynamicSSLSocketFactory(keyStoreProvider, passwordProvider);
    }

    @Test
    public void testGetDefaultCipherSuites() throws Exception {
        final String[] cipherSuites = factory.getDefaultCipherSuites();
        assertNotNull(cipherSuites);
        assertTrue(cipherSuites.length > 0);
    }

    @Test
    public void testGetSupportedCipherSuites() throws Exception {
        final String[] cipherSuites = factory.getSupportedCipherSuites();
        assertNotNull(cipherSuites);
        assertTrue(cipherSuites.length > 0);
    }

    @Test
    public void testCreateSocket() throws Exception {
        final String host = "google.com";
        when(keyStoreProvider.getKeyStore(host)).thenReturn(testKeyStore);
        when(keyStoreProvider.getTrustStore(host)).thenReturn(testTrustStore);

        try (final Socket socket = factory.createSocket(host, 443)) {
            assertNotNull(socket);
            assertTrue(socket.isConnected());
        }
    }
}