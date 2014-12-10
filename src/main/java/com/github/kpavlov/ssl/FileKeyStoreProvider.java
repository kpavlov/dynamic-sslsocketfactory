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

import org.slf4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static org.slf4j.LoggerFactory.getLogger;

public class FileKeyStoreProvider implements KeyStoreProvider, KeyPasswordProvider {

    private static final Logger LOGGER = getLogger(FileKeyStoreProvider.class);

    private final String keyStorePath;
    private final String trustStorePath;
    private final char[] keyStorePassword;
    private final char[] trustStorePassword;
    private final char[] keyPassword;

    public FileKeyStoreProvider(String keyStorePath,
                                char[] keyStorePassword,
                                String trustStorePath,
                                char[] trustStorePassword,
                                char[] keyPassword) {
        this.keyStorePath = keyStorePath;
        this.keyStorePassword = keyStorePassword;
        this.trustStorePassword = trustStorePassword;
        this.keyPassword = keyPassword;
        this.trustStorePath = trustStorePath;
    }

    @Override
    public KeyStore getKeyStore(String host) throws Exception{
        if (keyStorePath == null) {
            return null;
        }
        return loadKeyStore(keyStorePath, keyStorePassword);
    }

    @Override
    public KeyStore getTrustStore(String host) throws Exception{
        if (trustStorePath == null) {
            return null;
        }
        return loadKeyStore(trustStorePath, trustStorePassword);
    }

    @Override
    public char[] getPassword(String hostname) {
        return keyPassword;
    }

    private KeyStore loadKeyStore(String path, char[] storePassword) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        KeyStore trustStore;
        try {
            trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            LOGGER.error("Unable to create new KeyStore", e);
            throw e;
        }

        try (FileInputStream in = new FileInputStream(new File(path));) {
            trustStore.load(in, storePassword);
            return trustStore;
        } catch (Exception e) {
            LOGGER.error("Unable to read KeyStore from " + path, e);
            throw e;
        }
    }
}
