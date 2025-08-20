/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.sling.jcr.jackrabbit.accessmanager.impl;

import javax.jcr.security.AccessControlEntry;

import org.apache.jackrabbit.api.security.authorization.PrincipalAccessControlList;
import org.apache.sling.api.SlingJakartaHttpServletRequest;
import org.apache.sling.api.request.RequestPathInfo;
import org.apache.sling.api.resource.ResourceUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * Contains utility methods related to handling principal ace 
 */
public class PrincipalAceHelper {

    public static final String RESOURCE_PATH_REPOSITORY = "/:repository";

    private PrincipalAceHelper() {
        // no-op
    }

    /**
     * Calculates the effective path of the request resource
     * 
     * @param request the current request
     * @return the effect path
     */
    public static String getEffectivePath(SlingJakartaHttpServletRequest request) {
        String effectivePath = request.getResource().getPath();
        if (ResourceUtil.isNonExistingResource(request.getResource())) {
            // for non-existing resource trim the selectors and extension 
            //   off the resource path
            @NotNull
            RequestPathInfo requestPathInfo = request.getRequestPathInfo();
            @NotNull
            String resourcePath = requestPathInfo.getResourcePath();
            //trim the selectors and extension off the resource path
            @Nullable
            String extension = requestPathInfo.getExtension();
            if (extension != null) {
                resourcePath = resourcePath.substring(0, resourcePath.length() - extension.length() - 1);
            }
            @Nullable
            String selectorString = requestPathInfo.getSelectorString();
            if (selectorString != null) {
                resourcePath = resourcePath.substring(0, resourcePath.length() - selectorString.length() - 1);
            }

            if (PrincipalAceHelper.RESOURCE_PATH_REPOSITORY.equals(resourcePath)) {
                // special case
                effectivePath = null;
            } else {
                effectivePath = resourcePath;
            }
        }
        return effectivePath;
    }

    /**
     * Checks if the effective path of the entry is a match for the supplied
     * resource path
     * @param resourcePath the resource path to compare
     * @param entry the entry to get the effective path from
     * @return true if match, false otherwise
     */
    public static boolean matchesResourcePath(String resourcePath, AccessControlEntry entry) {
        boolean matches = false;
        if (entry instanceof PrincipalAccessControlList.Entry paclEntry) {
            String effectivePath = paclEntry.getEffectivePath();
            if (resourcePath == null) {
                matches = effectivePath == null;
            } else {
                matches = resourcePath.equals(effectivePath);
            }
        }
        return matches;
    }

}
