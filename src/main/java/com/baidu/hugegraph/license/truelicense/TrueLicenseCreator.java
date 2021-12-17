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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.prefs.Preferences;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.Charsets;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import com.baidu.hugegraph.license.LicenseCreateParam;
import com.baidu.hugegraph.license.LicenseExtraParam;
import com.baidu.hugegraph.util.E;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import de.schlichtherle.license.AbstractKeyStoreParam;
import de.schlichtherle.license.CipherParam;
import de.schlichtherle.license.DefaultCipherParam;
import de.schlichtherle.license.DefaultLicenseParam;
import de.schlichtherle.license.KeyStoreParam;
import de.schlichtherle.license.LicenseContent;
import de.schlichtherle.license.LicenseContentException;
import de.schlichtherle.license.LicenseManager;
import de.schlichtherle.license.LicenseParam;

public class TrueLicenseCreator {

    private static final X500Principal DEFAULT_ISSUER = new X500Principal(
            "CN=liningrui, OU=baidu, O=hugegraph, L=beijing, ST=beijing, C=cn");

    private static final Charset CHARSET = Charsets.UTF_8;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final LicenseCreateParam param;

    public TrueLicenseCreator(LicenseCreateParam param) {
        this.param = param;
    }

    public static TrueLicenseCreator build(String path) {
        File file = FileUtils.getFile(path);
        try {
            String json = FileUtils.readFileToString(file, CHARSET);
            LicenseCreateParam param = MAPPER.readValue(
                                       json, LicenseCreateParam.class);
            return new TrueLicenseCreator(param);
        } catch (Throwable e) {
            throw new IllegalArgumentException(String.format(
                      "Failed to parse json file '%s'", path), e);
        }
    }

    public void create() {
        File licenseFile = new File(this.param.licensePath());
        try {
            LicenseParam licenseParam = this.initLicenseParam();
            LicenseManager manager = new LicenseCreateManager(licenseParam);
            LicenseContent licenseContent = this.initLicenseContent();
            manager.store(licenseContent, licenseFile);
        } catch (Throwable e) {
            throw new IllegalArgumentException("Failed to generate license", e);
        }
    }

    private LicenseParam initLicenseParam() {
        Preferences preferences = Preferences.userNodeForPackage(
                                  TrueLicenseCreator.class);
        CipherParam cipherParam = new DefaultCipherParam(
                                  this.param.storePassword());
        KeyStoreParam keyStoreParam = new CustomKeyStoreParam(
                                      TrueLicenseCreator.class,
                                      this.param.privateKeyPath(),
                                      this.param.privateAlias(),
                                      this.param.storePassword(),
                                      this.param.keyPassword());
        return new DefaultLicenseParam(this.param.subject(), preferences,
                                       keyStoreParam, cipherParam);
    }

    private LicenseContent initLicenseContent() {
        LicenseContent content = new LicenseContent();
        content.setHolder(DEFAULT_ISSUER);
        content.setIssuer(DEFAULT_ISSUER);
        content.setSubject(this.param.subject());
        content.setIssued(this.param.issuedTime());
        content.setNotBefore(this.param.notBefore());
        content.setNotAfter(this.param.notAfter());
        content.setConsumerType(this.param.consumerType());
        content.setConsumerAmount(this.param.consumerAmount());
        content.setInfo(this.param.description());
        // Customized verification params
        String json;
        try {
            json = MAPPER.writeValueAsString(this.param.extraParams());
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to write extra params", e);
        }
        content.setExtra(json);
        return content;
    }

    /**
     * LicenseCreateManager is to validate extra-params when creating license
     */
    public static class LicenseCreateManager extends TrueLicenseManager {

        private static final Pattern IPV4_PATTERN = Pattern.compile(
                "^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}" +
                "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$"
        );
        private static final Pattern IPV6_PATTERN = Pattern.compile(
                "^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
        );

        private static final Pattern MAC_PATTERN = Pattern.compile(
                "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
        );

        public LicenseCreateManager(LicenseParam param) {
            super(param, null, null);
        }

        @Override
        protected synchronized void validateCreate(LicenseContent content)
                                    throws LicenseContentException {
            super.validateCreate(content);

            String extra = (String) content.getExtra();
            List<LicenseExtraParam> extraParams =
                                    TrueLicenseManager.parseExtraParams(extra);

            // Server ids cannot be duplicated
            List<String> ids = extraParams.stream().map(LicenseExtraParam::id)
                                          .collect(Collectors.toList());
            Set<String> dedupIds = new HashSet<>(ids);
            if (dedupIds.size() < ids.size()) {
                E.checkArgument(false,
                                "Please ensure there is no duplicated id " +
                                "in extra_params: %s", ids);
            }
            for (LicenseExtraParam param : extraParams) {
                // Do more check
                if (!StringUtils.isEmpty(param.ip())) {
                    E.checkArgument(IPV4_PATTERN.matcher(param.ip()).matches() ||
                                    IPV6_PATTERN.matcher(param.ip()).matches(),
                                    "Invalid ip address '%s'", param.ip());
                }
                if (!StringUtils.isEmpty(param.mac())) {
                    E.checkArgument(MAC_PATTERN.matcher(param.mac()).matches(),
                                    "Invalid mac address '%s'", param.mac());
                }
            }
        }
    }

    /**
     * Custom KeyStoreParam to store public and private key storage files to
     * other disk locations instead of projects
     */
    public static class CustomKeyStoreParam extends AbstractKeyStoreParam {

        private String storePath;
        private String keyAlias;
        private String keyPwd;
        private String storePwd;

        public CustomKeyStoreParam(Class<?> clazz, String storePath,
                                   String keyAlias, String storePwd,
                                   String keyPwd) {
            super(clazz, storePath);
            this.storePath = storePath;
            this.keyAlias = keyAlias;
            this.storePwd = storePwd;
            this.keyPwd = keyPwd;
        }

        @Override
        public String getAlias() {
            return this.keyAlias;
        }

        @Override
        public String getStorePwd() {
            return this.storePwd;
        }

        @Override
        public String getKeyPwd() {
            return this.keyPwd;
        }

        @Override
        public InputStream getStream() throws IOException {
            return new FileInputStream(new File(this.storePath));
        }
    }
}
