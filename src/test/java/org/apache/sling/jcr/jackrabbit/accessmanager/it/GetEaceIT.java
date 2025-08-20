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

import javax.jcr.RepositoryException;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.stream.Stream;

import jakarta.json.JsonArray;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;
import jakarta.servlet.http.HttpServletResponse;
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests for the 'eace' Sling Get Operation
 */
@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class GetEaceIT extends AccessManagerClientTestSupport {

    protected void commonEffectiveAceForUser(String selector) throws IOException, RepositoryException {
        testUserId = createTestUser();
        testFolderUrl = createTestFolder(
                null,
                "sling-tests1",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"child\" : { \"childPropOne\" : true } }");

        // 1. create an initial set of privileges
        List<NameValuePair> postParams = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_WRITE, PrivilegeValues.ALLOW)
                .build();
        addOrUpdateAce(testFolderUrl, postParams);

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");

        // fetch the JSON for the ace to verify the settings.
        String getUrl = testFolderUrl + "/child." + selector + ".json?pid=" + testUserId;

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject aceObject = parseJson(json);

        String principalString = aceObject.getString("principal");
        assertEquals(testUserId, principalString);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(1, privilegesObject.size());
        // allow privilege
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_WRITE);

        JsonObject declaredAtObj = aceObject.getJsonObject("declaredAt");
        assertNotNull(declaredAtObj);
        String testFolderPath = URI.create(testFolderUrl).getPath();
        assertEquals(testFolderPath, declaredAtObj.getString("node"));
    }

    /**
     * Effective ACE servlet returns correct information
     */
    @Test
    public void testEffectiveAceForUser() throws IOException, JsonException, RepositoryException {
        commonEffectiveAceForUser("eace");
    }

    /**
     * Effective ACE servlet returns correct information
     */
    @Test
    public void testTidyEffectiveAceForUser() throws IOException, JsonException, RepositoryException {
        commonEffectiveAceForUser("tidy.eace");
    }

    /**
     * Effective ACE servlet returns correct information
     */
    @Test
    public void testNoEffectiveAceForUser() throws IOException, JsonException, RepositoryException {
        testUserId = createTestUser();
        testUserId2 = createTestUser();
        testFolderUrl = createTestFolder(
                null,
                "sling-tests2",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"child\" : { \"childPropOne\" : true } }");

        // 1. create an initial set of privileges
        List<NameValuePair> postParams = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_WRITE, PrivilegeValues.ALLOW)
                .build();
        addOrUpdateAce(testFolderUrl, postParams);

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");

        // fetch the JSON for the ace to verify the settings.
        String getUrl = testFolderUrl + "/child.eace.json?pid=" + testUserId2;
        assertAuthenticatedHttpStatus(
                creds, getUrl, HttpServletResponse.SC_NOT_FOUND, "Did not expect an ace to be returned");
    }

    /**
     * Effective ACE servlet returns 404 when no read access rights permissions
     */
    @Test
    public void testNoAccessToEffectiveAceForUser() throws IOException, JsonException, RepositoryException {
        testUserId = createTestUser();
        testFolderUrl = createTestFolder(
                null,
                "sling-tests2",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"child\" : { \"childPropOne\" : true } }");

        // 1. create an initial set of privileges
        List<NameValuePair> postParams = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_READ_ACCESS_CONTROL, PrivilegeValues.DENY)
                .build();
        addOrUpdateAce(testFolderUrl, postParams);

        Credentials creds = new UsernamePasswordCredentials(testUserId, "testPwd");

        // fetch the JSON for the ace to verify the settings.
        String getUrl = testFolderUrl + ".eace.json?pid=" + testUserId;
        assertAuthenticatedHttpStatus(
                creds, getUrl, HttpServletResponse.SC_NOT_FOUND, "Did not expect an ace to be returned");
    }

    /**
     * ACE servlet returns restriction details for leaf of also allowed aggregate
     */
    @Test
    public void testEffectiveAceWithLeafRestrictionForUser() throws IOException, JsonException, RepositoryException {
        commonEffectiveAceWithLeafRestrictionForUser(1);
    }

    /**
     * ACE servlet returns restriction details for leaf of also allowed aggregate after a second
     * update to verify that the ordering doesn't get broken during update
     */
    @Test
    public void testEffectiveAceWithLeafRestrictionForUserAfterSecondUpdate()
            throws IOException, JsonException, RepositoryException {
        commonEffectiveAceWithLeafRestrictionForUser(2);
    }

    protected void commonEffectiveAceWithLeafRestrictionForUser(int numberOfUpdateAceCalls)
            throws IOException, RepositoryException {
        testUserId = createTestUser();
        testFolderUrl = createTestFolder(
                null,
                "sling-tests2",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"child\" : { \"childPropOne\" : true } }");

        // 1. create an initial set of privileges
        List<NameValuePair> postParams = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_ALL, PrivilegeValues.ALLOW)
                .withPrivilegeRestriction(
                        PrivilegeValues.ALLOW,
                        PrivilegeConstants.JCR_REMOVE_NODE,
                        AccessControlConstants.REP_GLOB,
                        "glob1")
                .build();
        for (int i = 0; i < numberOfUpdateAceCalls; i++) {
            addOrUpdateAce(testFolderUrl, postParams);
        }

        // fetch the JSON for the ace to verify the settings.
        String getUrl = testFolderUrl + "/child.eace.json?pid=" + testUserId;

        Credentials creds = new UsernamePasswordCredentials(testUserId, "testPwd");

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        assertNotNull(json);
        JsonObject aceObject = parseJson(json);

        String principalString = aceObject.getString("principal");
        assertEquals(testUserId, principalString);

        JsonObject eacePrivleges = aceObject.getJsonObject("privileges");
        assertNotNull(eacePrivleges);
        assertEquals(18, eacePrivleges.size());
        // allow privilege
        Stream.of(
                        PrivilegeConstants.JCR_MODIFY_ACCESS_CONTROL,
                        PrivilegeConstants.JCR_VERSION_MANAGEMENT,
                        PrivilegeConstants.JCR_READ,
                        PrivilegeConstants.REP_USER_MANAGEMENT,
                        PrivilegeConstants.JCR_ADD_CHILD_NODES,
                        PrivilegeConstants.JCR_NAMESPACE_MANAGEMENT,
                        PrivilegeConstants.JCR_READ_ACCESS_CONTROL,
                        PrivilegeConstants.JCR_NODE_TYPE_DEFINITION_MANAGEMENT,
                        PrivilegeConstants.JCR_LOCK_MANAGEMENT,
                        PrivilegeConstants.JCR_RETENTION_MANAGEMENT,
                        PrivilegeConstants.JCR_LIFECYCLE_MANAGEMENT,
                        PrivilegeConstants.JCR_NODE_TYPE_MANAGEMENT,
                        PrivilegeConstants.JCR_REMOVE_CHILD_NODES,
                        PrivilegeConstants.JCR_MODIFY_PROPERTIES,
                        PrivilegeConstants.REP_INDEX_DEFINITION_MANAGEMENT,
                        PrivilegeConstants.REP_PRIVILEGE_MANAGEMENT,
                        PrivilegeConstants.JCR_WORKSPACE_MANAGEMENT)
                .forEach(privilege -> {
                    assertPrivilege(eacePrivleges, true, PrivilegeValues.ALLOW, privilege, true, jsonValue -> {
                        assertNotNull(jsonValue);
                        assertEquals(JsonValue.TRUE, jsonValue);
                    });
                });
        assertPrivilege(
                eacePrivleges, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_REMOVE_NODE, true, jsonValue -> {
                    assertNotNull(jsonValue);
                    assertTrue(jsonValue instanceof JsonObject);
                    JsonObject restrictionsObj = (JsonObject) jsonValue;

                    JsonValue repGlobValue = restrictionsObj.get(AccessControlConstants.REP_GLOB);
                    assertNotNull(repGlobValue);
                    assertTrue(repGlobValue instanceof JsonString);
                    assertEquals("glob1", ((JsonString) repGlobValue).getString());
                });
    }

    /**
     * Verify that when the effective ace is a merge of ACEs in multiple
     * ancestor nodes, that an array of those node paths is returned in the
     * declaredAt structure
     */
    @Test
    public void testDeclaredAtArrayInEffectiveAceForUser() throws IOException, RepositoryException {
        testUserId = createTestUser();
        testFolderUrl = createTestFolder(
                null,
                "sling-tests1",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"child\" : { \"childPropOne\" : true } }");

        // 1. create an initial set of privileges
        List<NameValuePair> postParams = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_WRITE, PrivilegeValues.ALLOW)
                .build();
        addOrUpdateAce(testFolderUrl, postParams);

        List<NameValuePair> postParams2 = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_READ, PrivilegeValues.ALLOW)
                .build();
        addOrUpdateAce(testFolderUrl + "/child", postParams2);

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");

        // fetch the JSON for the ace to verify the settings.
        String getUrl = testFolderUrl + "/child.eace.json?pid=" + testUserId;

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject aceObject = parseJson(json);

        String principalString = aceObject.getString("principal");
        assertEquals(testUserId, principalString);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(2, privilegesObject.size());
        // allow privilege
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_WRITE);
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_READ);

        JsonObject declaredAtObj = aceObject.getJsonObject("declaredAt");
        assertNotNull(declaredAtObj);
        JsonValue nodeObj = declaredAtObj.get("node");
        assertTrue(nodeObj instanceof JsonArray);
        JsonArray nodeArray = (JsonArray) nodeObj;
        assertEquals(2, nodeArray.size());
        String testFolderPath = URI.create(testFolderUrl).getPath();
        assertTrue(nodeArray.get(0) instanceof JsonString);
        assertEquals(testFolderPath + "/child", ((JsonString) nodeArray.get(0)).getString());
        assertTrue(nodeArray.get(1) instanceof JsonString);
        assertEquals(testFolderPath, ((JsonString) nodeArray.get(1)).getString());
    }

    /**
     * Effective ACE servlet returns correct information
     */
    @Test
    public void testEffectiveAceForUserWithMergedRestrictionValues()
            throws IOException, JsonException, RepositoryException {
        testUserId = createTestUser();
        testFolderUrl = createTestFolder(
                null,
                "sling-tests2",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"child\" : { \"childPropOne\" : true, \"childPropTwo\" : \"two\" } }");

        // 0. ensure everyone has the privilege to read the test nodes
        List<NameValuePair> postParams = new AcePostParamsBuilder("everyone")
                .withPrivilege(PrivilegeConstants.REP_READ_NODES, PrivilegeValues.ALLOW)
                .build();
        addOrUpdateAce(testFolderUrl, postParams);

        // 1. create an initial set of privileges for the test user
        postParams = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.REP_READ_PROPERTIES, PrivilegeValues.DENY)
                .withPrivilegeRestriction(
                        PrivilegeValues.ALLOW,
                        PrivilegeConstants.REP_READ_PROPERTIES,
                        AccessControlConstants.REP_ITEM_NAMES,
                        "childPropOne")
                .build();
        addOrUpdateAce(testFolderUrl, postParams);

        // at this point the child JSON should have only one of the properties visible
        Credentials testUserCreds = new UsernamePasswordCredentials(testUserId, "testPwd");
        String getJsonContentUrl = testFolderUrl + "/child.json";
        String jsonContent =
                getAuthenticatedContent(testUserCreds, getJsonContentUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(jsonContent);
        JsonObject jsonObject = parseJson(jsonContent);
        assertTrue("Expected childPropOne property", jsonObject.containsKey("childPropOne"));
        assertFalse("Did not expect childPropTwo property", jsonObject.containsKey("childPropTwo"));

        // add ACE to the child to make the other property readable
        List<NameValuePair> postParams2 = new AcePostParamsBuilder(testUserId)
                .withPrivilegeRestriction(
                        PrivilegeValues.ALLOW,
                        PrivilegeConstants.REP_READ_PROPERTIES,
                        AccessControlConstants.REP_ITEM_NAMES,
                        "childPropTwo")
                .build();
        addOrUpdateAce(testFolderUrl + "/child", postParams2);

        // fetch the JSON for the ace to verify the settings.
        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String getUrl = testFolderUrl + "/child.eace.json?pid=" + testUserId;
        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject aceObject = parseJson(json);

        String principalString = aceObject.getString("principal");
        assertEquals(testUserId, principalString);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(1, privilegesObject.size());
        // allow privilege
        assertPrivilege(
                privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.REP_READ_PROPERTIES, jsonValue -> {
                    assertNotNull(jsonValue);
                    assertTrue(jsonValue instanceof JsonObject);
                    JsonObject restrictionsObj = (JsonObject) jsonValue;

                    // verify we have the merged restriction values
                    JsonValue itemNamesValue = restrictionsObj.get(AccessControlConstants.REP_ITEM_NAMES);
                    assertNotNull(itemNamesValue);
                    assertTrue(itemNamesValue instanceof JsonArray);
                    JsonArray itemNamesArray = (JsonArray) itemNamesValue;
                    assertEquals(2, itemNamesArray.size());
                    assertEquals("childPropOne", itemNamesArray.getString(0));
                    assertEquals("childPropTwo", itemNamesArray.getString(1));
                });

        // now verify that the JSON has both properties visible
        jsonContent =
                getAuthenticatedContent(testUserCreds, getJsonContentUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(jsonContent);
        jsonObject = parseJson(jsonContent);
        assertTrue("Expected childPropOne property", jsonObject.containsKey("childPropOne"));
        assertTrue("Expected childPropTwo property", jsonObject.containsKey("childPropTwo"));
    }
}
