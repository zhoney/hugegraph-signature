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

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

import com.baidu.hugegraph.license.CommonLicenseManager;
import com.baidu.hugegraph.license.ExtraParam;
import com.baidu.hugegraph.util.E;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import de.schlichtherle.license.LicenseContent;
import de.schlichtherle.license.LicenseContentException;
import de.schlichtherle.license.LicenseParam;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class LicenseCreateManager extends CommonLicenseManager {

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

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public LicenseCreateManager(LicenseParam param) {
        super(param);
    }

    @Override
    protected synchronized void validateCreate(LicenseContent content)
                                               throws LicenseContentException {
        super.validate(content);
        List<ExtraParam> extraParams;
        try {
            TypeReference type = new TypeReference<List<ExtraParam>>() {};
            extraParams = MAPPER.readValue((String) content.getExtra(), type);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read extra params", e);
        }
        // id cannot be same
        Set<String> ids = extraParams.stream().map(ExtraParam::id)
                                     .collect(Collectors.toSet());
        E.checkArgument(extraParams.size() == ids.size(),
                        "Please ensure there is no same id in extra_params %s",
                        extraParams);
        for (ExtraParam param : extraParams) {
            // do more check
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
