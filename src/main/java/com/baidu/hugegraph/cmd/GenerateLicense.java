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

package com.baidu.hugegraph.cmd;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FileUtils;

import com.baidu.hugegraph.license.truelicense.TrueLicenseCreator;

public class GenerateLicense {

    private static final String DIR = "src/main/resources/";

    public static void main(String[] args) throws IOException {
        String configPath = DIR + "create-license.json";
        TrueLicenseCreator creator = TrueLicenseCreator.build(configPath);
        creator.create();

        @SuppressWarnings("deprecation")
        String configContent = FileUtils.readFileToString(new File(configPath));
        System.out.printf("Generate license from config '%s':\n%s\n",
                          configPath, configContent);
    }
}
