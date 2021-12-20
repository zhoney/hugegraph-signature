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
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.prefs.Preferences;

import org.apache.commons.codec.Charsets;
import org.apache.commons.io.FileUtils;
import org.junit.After;
import org.junit.Test;

import com.baidu.hugegraph.license.LicenseExtraParam;
import com.baidu.hugegraph.license.LicenseInstallParam;
import com.baidu.hugegraph.license.LicenseParams;
import com.baidu.hugegraph.license.truelicense.TrueLicenseCreator.CustomKeyStoreParam;
import com.baidu.hugegraph.testutil.Assert;
import com.fasterxml.jackson.databind.ObjectMapper;

import de.schlichtherle.license.CipherParam;
import de.schlichtherle.license.DefaultCipherParam;
import de.schlichtherle.license.DefaultLicenseParam;
import de.schlichtherle.license.KeyStoreParam;
import de.schlichtherle.license.LicenseParam;
import de.schlichtherle.license.NoLicenseInstalledException;

public class TrueLicenseManagerTest {

    private static final Charset CHARSET = Charsets.UTF_8;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String DIR = "src/test/resources/";

    @After
    public void teardown() throws IOException {
        File lic = new File(DIR + "hugegraph-evaluation.license");
        FileUtils.forceDelete(lic);
    }

    @Test
    public void testVerifyLicenseWithInstall() throws Exception {
        String createConfigPath = DIR + "create-license.json";
        TrueLicenseCreator creator = TrueLicenseCreator.build(createConfigPath);
        creator.create();

        String verifyConfigPath = DIR + "verify-license.json";
        LicenseVerifier verifier = LicenseVerifier.build(verifyConfigPath,
                                                         "server-1", 2);
        verifier.install();
        verifier.verify();
    }

    @Test
    public void testVerifyLicenseWithoutInstall() throws Exception {
        String createConfigPath = DIR + "create-license.json";
        TrueLicenseCreator creator = TrueLicenseCreator.build(createConfigPath);
        creator.create();

        String verifyConfigPath = DIR + "verify-license.json";
        LicenseVerifier verifier = LicenseVerifier.build(verifyConfigPath,
                                                         "server-1", 2);
        verifier.verify();
    }

    @Test
    public void testVerifyLicenseWithReInstall() throws Exception {
        String createConfigPath = DIR + "create-license.json";
        TrueLicenseCreator creator = TrueLicenseCreator.build(createConfigPath);
        creator.create();

        String verifyConfigPath = DIR + "verify-license.json";
        LicenseVerifier verifier = LicenseVerifier.build(verifyConfigPath,
                                                         "server-1", 2);
        verifier.verify();

        verifier.uninstall();

        verifier.install();
        verifier.verify();
    }

    @Test
    public void testVerifyLicenseWithUninstall() throws Exception {
        String createConfigPath = DIR + "create-license.json";
        TrueLicenseCreator creator = TrueLicenseCreator.build(createConfigPath);
        creator.create();

        String verifyConfigPath = DIR + "verify-license.json";
        LicenseVerifier verifier = LicenseVerifier.build(verifyConfigPath,
                                                         "server-1", 3);
        verifier.uninstall();
        Assert.assertThrows(NoLicenseInstalledException.class, () -> {
            verifier.verify();
        }, e -> {
            Assert.assertContains("There is no license certificate installed",
                                  e.toString());
            Assert.assertEquals("hugegraph-evaluation", e.getMessage());
        });

        verifier.install();
        verifier.uninstall();
        Assert.assertThrows(NoLicenseInstalledException.class, () -> {
            verifier.verify();
        }, e -> {
            Assert.assertContains("There is no license certificate installed",
                                  e.toString());
            Assert.assertEquals("hugegraph-evaluation", e.getMessage());
        });
    }

    @Test
    public void testVerifyLicenseWithErrorId() throws Exception {
        String createConfigPath = DIR + "create-license.json";
        TrueLicenseCreator creator = TrueLicenseCreator.build(createConfigPath);
        creator.create();

        String verifyConfigPath = DIR + "verify-license.json";
        LicenseVerifier verifier = LicenseVerifier.build(verifyConfigPath,
                                                         "server-2", 3);
        Assert.assertThrows(IllegalStateException.class, () -> {
            verifier.install();
        }, e -> {
            Assert.assertContains("Failed to verify the extra license " +
                                  "parameters", e.toString());
            Assert.assertContains("The current server id 'server-2' is " +
                                  "not authorized", e.getCause().toString());
        });
    }

    @Test
    public void testVerifyLicenseWithExceedGraphs() throws Exception {
        String createConfigPath = DIR + "create-license.json";
        TrueLicenseCreator creator = TrueLicenseCreator.build(createConfigPath);
        creator.create();

        String verifyConfigPath = DIR + "verify-license.json";
        LicenseVerifier verifier = LicenseVerifier.build(verifyConfigPath,
                                                         "server-1", 4);
        Assert.assertThrows(IllegalStateException.class, () -> {
            verifier.install();
        }, e -> {
            Assert.assertContains("Failed to verify the extra license " +
                                  "parameters", e.toString());
            Assert.assertContains("The using graphs '4' exceeded authorized " +
                                  "limit '3'", e.getCause().toString());
        });
    }

    private static class LicenseVerifier {

        private final TrueLicenseManager manager;

        private final String serverId;
        private final int usingGraphs;

        public LicenseVerifier(LicenseInstallParam param,
                               String serverId, int usingGraphs) {
            this.manager = new TrueLicenseManager(wrapLicenseParam(param),
                                                  param, this::validate);
            this.serverId = serverId;
            this.usingGraphs = usingGraphs;
        }

        public void install() throws Exception {
            this.manager.installLicense();
        }

        public void uninstall() throws Exception {
            this.manager.uninstallLicense();
        }

        public void verify() throws Exception {
            this.manager.verifyLicense();
        }

        protected void validate(LicenseParams params) {
            // Verify the customized license parameters.
            LicenseExtraParam param = params.matchParam(this.serverId);
            if (param == null) {
                throw newLicenseException("The current server id '%s' " +
                                          "is not authorized", this.serverId);
            }
            if (this.usingGraphs > param.graphs()) {
                throw newLicenseException("The using graphs '%s' exceeded " +
                                          "authorized limit '%s'",
                                          this.usingGraphs, param.graphs());
            }
        }

        public static LicenseVerifier build(String path,
                                            String serverId, int usingGraphs)
                                            throws IOException {
            File file = FileUtils.getFile(path);
            String json;
            try {
                json = FileUtils.readFileToString(file, CHARSET);
            } catch (IOException e) {
                throw new RuntimeException(String.format(
                          "Failed to read file '%s'", path));
            }
            LicenseInstallParam param = MAPPER.readValue(
                                        json, LicenseInstallParam.class);
            return new LicenseVerifier(param, serverId, usingGraphs);
        }
    }

    private static LicenseParam wrapLicenseParam(LicenseInstallParam param) {
        Preferences preferences = Preferences.userNodeForPackage(
                                  TrueLicenseCreator.class);
        CipherParam cipherParam = new DefaultCipherParam(
                                  param.storePassword());
        KeyStoreParam keyStoreParam = new CustomKeyStoreParam(
                                      TrueLicenseManager.class,
                                      param.publicKeyPath(),
                                      param.publicAlias(),
                                      param.storePassword(),
                                      null);
        return new DefaultLicenseParam(param.subject(), preferences,
                                       keyStoreParam, cipherParam);
    }

    private static RuntimeException newLicenseException(String message,
                                                        Object... args) {
        return new IllegalStateException(String.format(message, args));
    }
}
