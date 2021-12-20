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

import org.apache.commons.io.FileUtils;
import org.junit.After;
import org.junit.Test;

import com.baidu.hugegraph.testutil.Assert;

public class TrueLicenseCreatorTest {

    private static final String DIR = "src/test/resources/";

    @After
    public void teardown() throws IOException {
        File lic = new File(DIR + "hugegraph-evaluation.license");
        if (lic.exists()) {
            FileUtils.forceDelete(lic);
        }
    }

    @Test
    public void testCreateLicense() throws Exception {
        File lic = new File(DIR + "hugegraph-evaluation.license");
        Assert.assertFalse(lic.exists());

        String createConfigPath = DIR + "create-license.json";
        TrueLicenseCreator creator = TrueLicenseCreator.build(createConfigPath);
        creator.create();

        Assert.assertTrue(lic.exists());
    }

    @Test
    public void testCreateLicenseWithDupId() throws Exception {
        File lic = new File(DIR + "hugegraph-evaluation.license");
        Assert.assertFalse(lic.exists());

        String createConfigPath = DIR + "create-license-dup-id.json";
        TrueLicenseCreator creator = TrueLicenseCreator.build(createConfigPath);

        Assert.assertThrows(IllegalArgumentException.class, () -> {
            creator.create();
        }, e -> {
            Assert.assertContains("Failed to generate license", e.getMessage());
            Assert.assertContains("Please ensure there is no duplicated id " +
                                  "in extra_params: " +
                                  "[server-1, server-1, server-2]",
                                  e.getCause().getMessage());
        });

        Assert.assertFalse(lic.exists());
    }

    @Test
    public void testCreateLicenseWithInvalidGraphs() throws Exception {
        File lic = new File(DIR + "hugegraph-evaluation.license");
        Assert.assertFalse(lic.exists());

        String createConfigPath = DIR + "create-license-invalid-graphs.json";

        Assert.assertThrows(IllegalArgumentException.class, () -> {
            TrueLicenseCreator.build(createConfigPath);
        }, e -> {
            Assert.assertContains("Failed to parse json file", e.getMessage());
            Assert.assertContains("Cannot deserialize value of type `int` " +
                                  "from String \"two\"",
                                  e.getCause().getMessage());
        });

        Assert.assertFalse(lic.exists());
    }

    @Test
    public void testCreateLicenseWithInvalidIp() throws Exception {
        File lic = new File(DIR + "hugegraph-evaluation.license");
        Assert.assertFalse(lic.exists());

        String createConfigPath = DIR + "create-license-invalid-ip.json";
        TrueLicenseCreator creator = TrueLicenseCreator.build(createConfigPath);

        Assert.assertThrows(IllegalArgumentException.class, () -> {
            creator.create();
        }, e -> {
            Assert.assertContains("Failed to generate license", e.getMessage());
            Assert.assertContains("Invalid ip address '8.8.8.888'",
                                  e.getCause().getMessage());
        });

        Assert.assertFalse(lic.exists());
    }

    @Test
    public void testCreateLicenseWithInvalidMac() throws Exception {
        File lic = new File(DIR + "hugegraph-evaluation.license");
        Assert.assertFalse(lic.exists());

        String createConfigPath = DIR + "create-license-invalid-mac.json";
        TrueLicenseCreator creator = TrueLicenseCreator.build(createConfigPath);

        Assert.assertThrows(IllegalArgumentException.class, () -> {
            creator.create();
        }, e -> {
            Assert.assertContains("Failed to generate license", e.getMessage());
            Assert.assertContains("Invalid mac address '123'",
                                  e.getCause().getMessage());
        });

        Assert.assertFalse(lic.exists());
    }
}
