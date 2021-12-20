/*
 * Copyright 2017 HugeGraph Authors
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to You under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.baidu.hugegraph.license.truelicense;

import java.beans.XMLDecoder;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.prefs.Preferences;

import org.slf4j.Logger;

import com.baidu.hugegraph.license.LicenseExtraParam;
import com.baidu.hugegraph.license.LicenseInstallParam;
import com.baidu.hugegraph.license.LicenseManager;
import com.baidu.hugegraph.license.LicenseParams;
import com.baidu.hugegraph.util.Log;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import de.schlichtherle.license.CipherParam;
import de.schlichtherle.license.DefaultCipherParam;
import de.schlichtherle.license.DefaultKeyStoreParam;
import de.schlichtherle.license.DefaultLicenseParam;
import de.schlichtherle.license.KeyStoreParam;
import de.schlichtherle.license.LicenseContent;
import de.schlichtherle.license.LicenseContentException;
import de.schlichtherle.license.LicenseNotary;
import de.schlichtherle.license.LicenseParam;
import de.schlichtherle.license.NoLicenseInstalledException;
import de.schlichtherle.xml.GenericCertificate;

public class TrueLicenseManager extends de.schlichtherle.license.LicenseManager
                                implements LicenseManager {

    private static final Logger LOG = Log.logger(TrueLicenseManager.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String CHARSET = "UTF-8";
    private static final int BUF_SIZE = 8 * 1024;

    private final LicenseInstallParam licenseInstallParam;
    private final VerifyCallback verifyCallback;

    public TrueLicenseManager(LicenseInstallParam licenseInstallParam,
                              VerifyCallback veryfyCallback) {
        this(wrapLicenseParam(licenseInstallParam),
             licenseInstallParam, veryfyCallback);
    }

    protected TrueLicenseManager(LicenseParam licenseParam,
                                 LicenseInstallParam licenseInstallParam,
                                 VerifyCallback veryfyCallback) {
        super(licenseParam);
        this.licenseInstallParam = licenseInstallParam;
        this.verifyCallback = veryfyCallback;
    }

    @Override
    public LicenseParams installLicense() throws Exception {
        File licenseFile = new File(this.licenseInstallParam.licensePath());
        return transLicenseContent(super.install(licenseFile));
    }

    @Override
    public void uninstallLicense() throws Exception {
        super.uninstall();
    }

    @Override
    public LicenseParams verifyLicense() throws Exception {
        return transLicenseContent(super.verify());
    }

    @Override
    protected synchronized byte[] create(LicenseContent content,
                                         LicenseNotary notary)
                                         throws Exception {
        super.initialize(content);
        this.validateCreate(content);
        GenericCertificate certificate = notary.sign(content);
        return super.getPrivacyGuard().cert2key(certificate);
    }

    @Override
    protected synchronized LicenseContent install(byte[] key,
                                                  LicenseNotary notary)
                                                  throws Exception {
        GenericCertificate certificate = super.getPrivacyGuard().key2cert(key);
        notary.verify(certificate);
        String encodedText = certificate.getEncoded();
        LicenseContent content = (LicenseContent) this.load(encodedText);
        this.validate(content);
        super.setLicenseKey(key);
        super.setCertificate(certificate);
        return content;
    }

    @Override
    protected synchronized LicenseContent verify(LicenseNotary notary)
                                                 throws Exception {
        // Load license key from preferences
        byte[] key = super.getLicenseKey();
        if (key == null) {
            String subject = super.getLicenseParam().getSubject();
            throw new NoLicenseInstalledException(subject);
        }

        GenericCertificate certificate = super.getPrivacyGuard().key2cert(key);
        notary.verify(certificate);
        String encodedText = certificate.getEncoded();
        LicenseContent content = (LicenseContent) this.load(encodedText);
        this.validate(content);
        super.setCertificate(certificate);
        return content;
    }

    @Override
    protected synchronized void validate(LicenseContent content)
                                         throws LicenseContentException {
        // Call super validate firstly to verify the common license parameters
        super.validate(content);

        // Call user callback to verify the extra license parameters
        LicenseParams params = transLicenseContent(content);
        try {
            this.verifyCallback.onVerifyLicense(params);
        } catch (Exception e) {
            LOG.error("Failed to verify the extra license parameters", e);
            throw new IllegalStateException(
                      "Failed to verify the extra license parameters", e);
        }
    }

    protected synchronized void validateCreate(LicenseContent content)
                                               throws LicenseContentException {
        // Just call super validate is ok
        super.validate(content);
    }

    private Object load(String text) throws Exception {
        InputStream bis = null;
        XMLDecoder decoder = null;
        try {
            bis = new ByteArrayInputStream(text.getBytes(CHARSET));
            decoder = new XMLDecoder(new BufferedInputStream(bis, BUF_SIZE));
            return decoder.readObject();
        } catch (UnsupportedEncodingException e) {
            throw new LicenseContentException(String.format(
                      "Unsupported charset: %s", CHARSET));
        } finally {
            if (decoder != null) {
                decoder.close();
            }
            try {
                if (bis != null) {
                    bis.close();
                }
            } catch (Exception e) {
                LOG.warn("Failed to close stream", e);
            }
        }
    }

    private static LicenseParam wrapLicenseParam(LicenseInstallParam param) {
        Preferences preferences = Preferences.userNodeForPackage(
                                  TrueLicenseManager.class);
        CipherParam cipherParam = new DefaultCipherParam(
                                  param.storePassword());
        KeyStoreParam keyStoreParam = new DefaultKeyStoreParam(
                                      TrueLicenseManager.class,
                                      param.publicKeyPath(),
                                      param.publicAlias(),
                                      param.storePassword(),
                                      null);
        return new DefaultLicenseParam(param.subject(), preferences,
                                       keyStoreParam, cipherParam);
    }

    protected static LicenseParams transLicenseContent(LicenseContent content) {
        List<LicenseExtraParam> extraParams = parseExtraParams(
                                              (String) content.getExtra());

        LicenseParams params = new LicenseParams(content.getSubject(),
                                                 content.getInfo(),
                                                 content.getIssued(),
                                                 content.getNotBefore(),
                                                 content.getNotAfter(),
                                                 content.getConsumerType(),
                                                 content.getConsumerAmount(),
                                                 extraParams);
        return params;
    }

    protected static List<LicenseExtraParam> parseExtraParams(String extra) {
        try {
            TypeReference<List<LicenseExtraParam>> type;
            type = new TypeReference<List<LicenseExtraParam>>() { };
            return MAPPER.readValue(extra, type);
        } catch (Throwable e) {
            LOG.error("Failed to read extra params", e);
            throw new IllegalStateException("Failed to read extra params", e);
        }
    }
}
