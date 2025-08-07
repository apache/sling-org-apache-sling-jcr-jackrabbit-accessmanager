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
package org.apache.sling.jcr.jackrabbit.accessmanager.it;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.stream.Stream;

import javax.jcr.RepositoryException;

import org.apache.http.NameValuePair;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.AccessControlConstants;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;

import jakarta.json.JsonArray;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Tests for the 'pace' Sling Get Operation
 */
@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class GetPaceIT extends PrincipalAceTestSupport {

    /**
     * Privilege ACE servlet returns correct information
     */
    @SuppressWarnings("java:S2699")
    @Test
    public void testPrivilegeAceForServiceUser() throws IOException, JsonException {
        commonPrivilegeAceForServiceUser("pace");
    }

    /**
     * Privilege ACE servlet returns correct information
     */
    @SuppressWarnings("java:S2699")
    @Test
    public void testTidyPrivilegeAceForServiceUser() throws IOException, JsonException {
        commonPrivilegeAceForServiceUser("tidy.pace");
    }

    /**
     * Privilege ACE servlet returns correct information
     */
    @Test
    public void testNoPrivilegeAceForServiceUser() throws IOException, JsonException {
        String testServiceUserId = "pacetestuser";
        testFolderUrl = createTestFolder(null, "sling-tests2",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"child\" : { \"childPropOne\" : true } }");

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");

        //fetch the JSON for the principal ace to verify the settings.
        String getUrl = testFolderUrl + ".pace.json?pid=" + testServiceUserId;

        // no declared principal access control entry returns a 404
        assertAuthenticatedHttpStatus(creds, getUrl, HttpServletResponse.SC_NOT_FOUND, "Did not expect an ace to be returned");
    }

    /**
     * Privilege ACE servlet returns 404 when no read access rights permissions
     */
    @Test
    public void testNoAccessToPrivilegeAceForUser() throws IOException, JsonException, RepositoryException {
        String testServiceUserId = "pacetestuser";
        testFolderUrl = createTestFolder(null, "sling-tests1",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"child\" : { \"childPropOne\" : true } }");

        //1. create an initial set of privileges for the service user
        List<NameValuePair> postParams = new AcePostParamsBuilder(testServiceUserId)
                .withPrivilege(PrivilegeConstants.JCR_WRITE, PrivilegeValues.ALLOW)
                .build();
        addOrUpdatePrincipalAce(testFolderUrl, postParams);

        //1. create an initial set of privileges for the client user
        testUserId = createTestUser();
        List<NameValuePair> postParams2 = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_READ_ACCESS_CONTROL, PrivilegeValues.DENY)
                .build();
        addOrUpdateAce(testFolderUrl, postParams2);

        Credentials creds = new UsernamePasswordCredentials(testUserId, "testPwd");

        //fetch the JSON for the ace to verify the settings.
        String getUrl = testFolderUrl + ".pace.json?pid=" + testUserId;
        assertAuthenticatedHttpStatus(creds, getUrl, HttpServletResponse.SC_NOT_FOUND, "Did not expect an ace to be returned");
    }

    /**
     * Privilege ACE servlet returns correct information
     */
    @SuppressWarnings("java:S2699")
    @Test
    public void testPrivilegeAceForServiceUserOnNullPath() throws IOException, JsonException {
        String targetUrl = String.format("%s/:repository", baseServerUri);
        commonPrivilegeAceForServiceUser(targetUrl, "pace");
    }

    /**
     * Privilege ACE servlet returns correct information
     */
    @SuppressWarnings("java:S2699")
    @Test
    public void testPrivilegeAceForServiceUserOnNotExistingPath() throws IOException, JsonException {
        String targetUrl = String.format("%s/not_existing_path", baseServerUri);
        commonPrivilegeAceForServiceUser(targetUrl, "pace");
    }


    /**
     * ACE servlet returns restriction details for leaf of also allowed aggregate
     */
    @Test
    public void testPrivilegeAceWithLeafRestrictionForUser() throws IOException, JsonException {
        commonPrivilegeAceWithLeafRestrictionForUser(1);
    }

    /**
     * ACE servlet returns restriction details for leaf of also allowed aggregate after a second
     * update to verify that the ordering doesn't get broken during update
     */
    @Test
    public void testPrivilegeAceWithLeafRestrictionForUserAfterSecondUpdate() throws IOException, JsonException {
        commonPrivilegeAceWithLeafRestrictionForUser(2);
    }

    protected void commonPrivilegeAceWithLeafRestrictionForUser(int numberOfUpdateAceCalls) throws IOException {
        testFolderUrl = createTestFolder(null, "sling-tests",
                "{ \"jcr:primaryType\": \"nt:unstructured\" }");
        String testServiceUserId = "pacetestuser";

        //1. create an initial set of privileges
        List<NameValuePair> postParams = new AcePostParamsBuilder(testServiceUserId)
                .withPrivilege(PrivilegeConstants.JCR_ALL, PrivilegeValues.ALLOW)
                .withPrivilegeRestriction(PrivilegeValues.ALLOW, PrivilegeConstants.JCR_REMOVE_NODE, AccessControlConstants.REP_GLOB, "glob1")
                .build();
        for (int i=0; i < numberOfUpdateAceCalls; i++) {
            addOrUpdatePrincipalAce(testFolderUrl, postParams);
        }

        JsonObject principalAce = getPrincipalAce(testFolderUrl, testServiceUserId);
        JsonObject acePrivleges = principalAce.getJsonObject("privileges");
        assertNotNull(acePrivleges);
        assertEquals(18, acePrivleges.size());
        //allow privilege
        Stream.of(PrivilegeConstants.JCR_MODIFY_ACCESS_CONTROL, PrivilegeConstants.JCR_VERSION_MANAGEMENT,
                PrivilegeConstants.JCR_READ, PrivilegeConstants.REP_USER_MANAGEMENT,
                PrivilegeConstants.JCR_ADD_CHILD_NODES, PrivilegeConstants.JCR_NAMESPACE_MANAGEMENT,
                PrivilegeConstants.JCR_READ_ACCESS_CONTROL, PrivilegeConstants.JCR_NODE_TYPE_DEFINITION_MANAGEMENT,
                PrivilegeConstants.JCR_LOCK_MANAGEMENT, PrivilegeConstants.JCR_RETENTION_MANAGEMENT,
                PrivilegeConstants.JCR_LIFECYCLE_MANAGEMENT, PrivilegeConstants.JCR_NODE_TYPE_MANAGEMENT,
                PrivilegeConstants.JCR_REMOVE_CHILD_NODES, PrivilegeConstants.JCR_MODIFY_PROPERTIES,
                PrivilegeConstants.REP_INDEX_DEFINITION_MANAGEMENT, PrivilegeConstants.REP_PRIVILEGE_MANAGEMENT,
                PrivilegeConstants.JCR_WORKSPACE_MANAGEMENT)
            .forEach(privilege -> {
                assertPrivilege(acePrivleges, true, PrivilegeValues.ALLOW, privilege,
                        true, jsonValue -> {
                            assertNotNull(jsonValue);
                            assertEquals(JsonValue.TRUE, jsonValue);
                        });
            });
        assertPrivilege(acePrivleges, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_REMOVE_NODE,
                true, jsonValue -> {
                    assertNotNull(jsonValue);
                    assertTrue(jsonValue instanceof JsonObject);
                    JsonObject restrictionsObj = (JsonObject)jsonValue;

                    JsonValue repGlobValue = restrictionsObj.get(AccessControlConstants.REP_GLOB);
                    assertNotNull(repGlobValue);
                    assertTrue(repGlobValue instanceof JsonString);
                    assertEquals("glob1", ((JsonString)repGlobValue).getString());
                });
    }

    /**
     * Verify that when the effective ace is a merge of ACEs in multiple
     * ancestor nodes, that an array of those node paths is returned in the
     * declaredAt structure
     */
    @Test
    public void testDeclaredAtArrayInEffectiveAceForServiceUser() throws IOException {
        testFolderUrl = createTestFolder(null, "sling-tests5",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"child\" : { \"childPropOne\" : true } }");
        String testServiceUserId = "pacetestuser";

        //1. create an initial set of privileges
        List<NameValuePair> postParams = new AcePostParamsBuilder(testServiceUserId)
                .withPrivilege(PrivilegeConstants.JCR_WRITE, PrivilegeValues.ALLOW)
                .build();
        addOrUpdatePrincipalAce(testFolderUrl, postParams);

        List<NameValuePair> postParams2 = new AcePostParamsBuilder(testServiceUserId)
                .withPrivilege(PrivilegeConstants.JCR_READ, PrivilegeValues.ALLOW)
                .build();
        addOrUpdatePrincipalAce(testFolderUrl + "/child", postParams2);

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");

        //fetch the JSON for the ace to verify the settings.
        String getUrl = testFolderUrl + "/child.eace.json?pid=" + testServiceUserId;

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject aceObject = parseJson(json);

        String principalString = aceObject.getString("principal");
        assertEquals(testServiceUserId, principalString);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(2, privilegesObject.size());
        //allow privilege
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_WRITE);
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_READ);

        JsonObject declaredAtObj = aceObject.getJsonObject("declaredAt");
        assertNotNull(declaredAtObj);
        JsonValue nodeObj = declaredAtObj.get("principal");
        assertTrue (nodeObj instanceof JsonArray);
        JsonArray nodeArray = (JsonArray)nodeObj;
        assertEquals(2, nodeArray.size());
        String testFolderPath = URI.create(testFolderUrl).getPath();
        assertTrue (nodeArray.get(0) instanceof JsonString);
        assertEquals(testFolderPath + "/child", ((JsonString)nodeArray.get(0)).getString());
        assertTrue (nodeArray.get(1) instanceof JsonString);
        assertEquals(testFolderPath, ((JsonString)nodeArray.get(1)).getString());
    }

}
