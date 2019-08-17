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

package com.baidu.hugegraph;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.prefs.Preferences;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.Charsets;
import org.apache.commons.io.FileUtils;

import com.baidu.hugegraph.license.FileKeyStoreParam;
import com.baidu.hugegraph.license.LicenseCreateParam;
import com.baidu.hugegraph.util.JsonUtil;

import de.schlichtherle.license.CipherParam;
import de.schlichtherle.license.DefaultCipherParam;
import de.schlichtherle.license.DefaultLicenseParam;
import de.schlichtherle.license.KeyStoreParam;
import de.schlichtherle.license.LicenseContent;
import de.schlichtherle.license.LicenseManager;
import de.schlichtherle.license.LicenseParam;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class LicenseCreator {

    private static final Charset CHARSET = Charsets.UTF_8;
    private static final X500Principal DEFAULT_ISSUER = new X500Principal(
            "CN=liningrui, OU=baidu, O=xbu-data, L=beijing, ST=beijing, C=cn");

    private final LicenseCreateParam param;

    public LicenseCreator(LicenseCreateParam param) {
        this.param = param;
    }

    public static LicenseCreator build(String path) {
        File file = FileUtils.getFile(path);
        String json;
        try {
            json = FileUtils.readFileToString(file, CHARSET);
        } catch (IOException e) {
            throw new RuntimeException(String.format(
                      "Failed to read file '%s'", path));
        }
        LicenseCreateParam param = JsonUtil.fromJson(json, LicenseCreateParam.class);
        return new LicenseCreator(param);
    }

    private void create(){
        try {
            LicenseParam licenseParam = this.initLicenseParam();
            LicenseManager licenseManager = new LicenseCreateManager(licenseParam);
            LicenseContent licenseContent = this.initLicenseContent();
            File licenseFile = new File(this.param.licensePath());
            licenseManager.store(licenseContent, licenseFile);
            log.info("Generate license succeed at path {}", licenseFile.getPath());
        } catch (Exception e){
            throw new RuntimeException("Generate license failed", e);
        }
    }

    private LicenseParam initLicenseParam(){
        Preferences preferences = Preferences.userNodeForPackage(LicenseCreator.class);
        CipherParam cipherParam = new DefaultCipherParam(this.param.storePassword());
        KeyStoreParam keyStoreParam;
        keyStoreParam = new FileKeyStoreParam(LicenseCreator.class,
                                              this.param.privateKeyPath(),
                                              this.param.privateAlias(),
                                              this.param.storePassword(),
                                              this.param.keyPassword());
        return new DefaultLicenseParam(this.param.subject(), preferences,
                                       keyStoreParam, cipherParam);
    }

    private LicenseContent initLicenseContent(){
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
        content.setExtra(JsonUtil.toJson(this.param.extraParams()));
        return content;
    }

    public static void main(String[] args) {
        String path = "/Users/liningrui/IdeaProjects/hugegraph-signature/src/main/resources/create-license.json";
        LicenseCreator creator = LicenseCreator.build(path);
        creator.create();
    }
}
