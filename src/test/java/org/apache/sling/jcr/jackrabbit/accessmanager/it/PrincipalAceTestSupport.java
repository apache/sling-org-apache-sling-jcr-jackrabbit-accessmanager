/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sling.jcr.jackrabbit.accessmanager.it;

import java.io.IOException;
import java.util.List;

import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.http.NameValuePair;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.ops4j.pax.exam.Option;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.ops4j.pax.exam.CoreOptions.composite;
import static org.ops4j.pax.exam.CoreOptions.mavenBundle;
import static org.ops4j.pax.exam.cm.ConfigurationAdminOptions.factoryConfiguration;
import static org.ops4j.pax.exam.cm.ConfigurationAdminOptions.newConfiguration;

/**
 * Base class for testing of the principal ACE operations
 */
public abstract class PrincipalAceTestSupport extends AccessManagerClientTestSupport {

    @Override
    protected Option[] additionalOptions() throws IOException {
        return composite(super.additionalOptions())
                .add(
                        mavenBundle()
                                .groupId("org.apache.jackrabbit")
                                .artifactId("oak-authorization-principalbased")
                                .version("1.48.0"),
                        newConfiguration(
                                        "org.apache.jackrabbit.oak.spi.security.authorization.principalbased.impl.PrincipalBasedAuthorizationConfiguration")
                                .put("enableAggregationFilter", true)
                                .asOption(),
                        newConfiguration(
                                        "org.apache.jackrabbit.oak.spi.security.authorization.principalbased.impl.FilterProviderImpl")
                                .put("path", "/home/users/system/sling")
                                .asOption(),
                        newConfiguration("org.apache.jackrabbit.oak.security.internal.SecurityProviderRegistration")
                                .put("requiredServicePids", new String[] {
                                    "org.apache.jackrabbit.oak.security.authorization.AuthorizationConfigurationImpl",
                                    "org.apache.jackrabbit.oak.security.principal.PrincipalConfigurationImpl",
                                    "org.apache.jackrabbit.oak.security.authentication.token.TokenConfigurationImpl",
                                    "org.apache.jackrabbit.oak.spi.security.user.action.DefaultAuthorizableActionProvider",
                                    "org.apache.jackrabbit.oak.security.authorization.restriction.RestrictionProviderImpl",
                                    "org.apache.jackrabbit.oak.security.user.UserAuthenticationFactoryImpl",
                                    "org.apache.jackrabbit.oak.spi.security.authorization.principalbased.impl.PrincipalBasedAuthorizationConfiguration"
                                })
                                .asOption(),
                        factoryConfiguration("org.apache.sling.jcr.repoinit.RepositoryInitializer")
                                .put("scripts", new String[] {
                                    """
                                create service user pacetestuser with path /home/users/system/sling
                                create service user pacetestuser2 with path /home/users/system/sling
                                """
                                })
                                .asOption())
                .getOptions();
    }

    protected void addOrUpdatePrincipalAce(String folderUrl, List<NameValuePair> postParams)
            throws IOException, JsonException {
        addOrUpdatePrincipalAce(folderUrl, postParams, HttpServletResponse.SC_OK);
    }

    protected void addOrUpdatePrincipalAce(String folderUrl, List<NameValuePair> postParams, int expectedStatus)
            throws IOException, JsonException {
        String postUrl = folderUrl + ".modifyPAce.html";

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, expectedStatus, postParams, null);
    }

    protected String addOrUpdatePrincipalAce(String folderUrl, List<NameValuePair> postParams, String contentType)
            throws IOException, JsonException {
        return addOrUpdatePrincipalAce(folderUrl, postParams, contentType, HttpServletResponse.SC_OK);
    }

    protected String addOrUpdatePrincipalAce(
            String folderUrl, List<NameValuePair> postParams, String contentType, int expectedStatus)
            throws IOException, JsonException {
        String postUrl = folderUrl + ".modifyPAce." + (CONTENT_TYPE_JSON.equals(contentType) ? "json" : "html");

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        return getAuthenticatedPostContent(creds, postUrl, contentType, postParams, expectedStatus);
    }

    protected void commonPrivilegeAceForServiceUser(String selector) throws IOException {
        testFolderUrl = createTestFolder(
                null,
                "sling-tests1",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"child\" : { \"childPropOne\" : true } }");
        commonPrivilegeAceForServiceUser(testFolderUrl, selector);
    }

    protected void commonPrivilegeAceForServiceUser(String testUrl, String selector) throws IOException {
        String testServiceUserId = "pacetestuser";

        // 1. create an initial set of privileges
        List<NameValuePair> postParams = new AcePostParamsBuilder(testServiceUserId)
                .withPrivilege(PrivilegeConstants.JCR_WRITE, PrivilegeValues.ALLOW)
                .build();
        addOrUpdatePrincipalAce(testUrl, postParams);

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");

        // fetch the JSON for the principal ace to verify the settings.
        String getUrl = testUrl + "." + selector + ".json?pid=" + testServiceUserId;

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject aceObject = parseJson(json);

        String principalString = aceObject.getString("principal");
        assertEquals(testServiceUserId, principalString);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(1, privilegesObject.size());
        // allow privilege
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_WRITE);
    }
}
