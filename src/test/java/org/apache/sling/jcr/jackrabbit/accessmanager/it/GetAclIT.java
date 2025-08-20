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
import java.util.List;

import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.http.NameValuePair;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests for the 'acl' and 'eacl' Sling Get Operation
 */
@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class GetAclIT extends AccessManagerClientTestSupport {

    /**
     * Test for SLING-2600, Effective ACL servlet returns incorrect information
     */
    @Test
    public void testEffectiveAclForUser() throws IOException, JsonException, RepositoryException {
        testUserId = createTestUser();
        testUserId2 = createTestUser();

        testFolderUrl = createTestFolder(
                null,
                "sling-tests",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"propOne\" : \"propOneValue\", \"child\" : { \"childPropOne\" : true } }");

        // 1. create an initial set of privileges
        List<NameValuePair> postParams = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_WRITE, PrivilegeValues.ALLOW)
                .build();
        addOrUpdateAce(testFolderUrl, postParams);

        List<NameValuePair> postParams2 = new AcePostParamsBuilder(testUserId2)
                .withPrivilege(PrivilegeConstants.JCR_WRITE, PrivilegeValues.ALLOW)
                .build();
        addOrUpdateAce(testFolderUrl, postParams2);

        List<NameValuePair> postParams3 = new AcePostParamsBuilder(testUserId2)
                .withPrivilege(PrivilegeConstants.JCR_LOCK_MANAGEMENT, PrivilegeValues.ALLOW)
                .build();
        addOrUpdateAce(testFolderUrl + "/child", postParams3);

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");

        // fetch the JSON for the eacl to verify the settings.
        String getUrl = testFolderUrl + "/child.eacl.json";

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject jsonObject = parseJson(json);

        JsonObject aceObject = jsonObject.getJsonObject(testUserId);
        assertNotNull(aceObject);

        String principalString = aceObject.getString("principal");
        assertEquals(testUserId, principalString);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(1, privilegesObject.size());
        // allow privilege
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_WRITE);

        JsonObject aceObject2 = jsonObject.getJsonObject(testUserId2);
        assertNotNull(aceObject2);

        String principalString2 = aceObject2.getString("principal");
        assertEquals(testUserId2, principalString2);

        JsonObject privilegesObject2 = aceObject2.getJsonObject("privileges");
        assertNotNull(privilegesObject2);
        assertEquals(2, privilegesObject2.size());
        // allow privilege
        assertPrivilege(privilegesObject2, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_WRITE);
        assertPrivilege(privilegesObject2, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_LOCK_MANAGEMENT);
    }

    /**
     * Test for SLING-2600, Effective ACL servlet returns incorrect information
     */
    @Test
    public void testEffectiveAclMergeForUserReplacePrivilegeOnChild()
            throws IOException, JsonException, RepositoryException {
        testUserId = createTestUser();

        testFolderUrl = createTestFolder(
                null,
                "sling-tests",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"propOne\" : \"propOneValue\", \"child\" : { \"childPropOne\" : true } }");

        // 1. create an initial set of privileges
        List<NameValuePair> postParams = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_WRITE, PrivilegeValues.DENY)
                .build();
        addOrUpdateAce(testFolderUrl, postParams);

        List<NameValuePair> postParams3 = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_WRITE, PrivilegeValues.ALLOW)
                .build();
        addOrUpdateAce(testFolderUrl + "/child", postParams3);

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");

        // fetch the JSON for the eacl to verify the settings.
        String getUrl = testFolderUrl + "/child.eacl.json";

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject jsonObject = parseJson(json);

        JsonObject aceObject = jsonObject.getJsonObject(testUserId);
        assertNotNull(aceObject);

        String principalString = aceObject.getString("principal");
        assertEquals(testUserId, principalString);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(1, privilegesObject.size());
        // allow privilege
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_WRITE);
    }

    /**
     * Test for SLING-2600, Effective ACL servlet returns incorrect information
     */
    @Test
    public void testEffectiveAclMergeForUserFewerPrivilegesGrantedOnChild()
            throws IOException, JsonException, RepositoryException {
        testUserId = createTestUser();

        testFolderUrl = createTestFolder(
                null,
                "sling-tests",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"propOne\" : \"propOneValue\", \"child\" : { \"childPropOne\" : true } }");

        List<NameValuePair> postParams = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_ALL, PrivilegeValues.ALLOW)
                .build();
        addOrUpdateAce(testFolderUrl, postParams);

        List<NameValuePair> postParams3 = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_WRITE, PrivilegeValues.ALLOW)
                .build();
        addOrUpdateAce(testFolderUrl + "/child", postParams3);

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");

        // fetch the JSON for the eacl to verify the settings.
        String getUrl = testFolderUrl + "/child.eacl.json";

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject jsonObject = parseJson(json);

        JsonObject aceObject = jsonObject.getJsonObject(testUserId);
        assertNotNull(aceObject);

        String principalString = aceObject.getString("principal");
        assertEquals(testUserId, principalString);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(1, privilegesObject.size());
        // allow privilege
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_ALL);
    }

    /**
     * Test for SLING-2600, Effective ACL servlet returns incorrect information
     */
    @Test
    public void testEffectiveAclMergeForUserMorePrivilegesGrantedOnChild()
            throws IOException, JsonException, RepositoryException {
        testUserId = createTestUser();

        testFolderUrl = createTestFolder(
                null,
                "sling-tests",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"propOne\" : \"propOneValue\", \"child\" : { \"childPropOne\" : true } }");

        List<NameValuePair> postParams = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_WRITE, PrivilegeValues.ALLOW)
                .build();
        addOrUpdateAce(testFolderUrl, postParams);

        List<NameValuePair> postParams3 = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_ALL, PrivilegeValues.ALLOW)
                .build();
        addOrUpdateAce(testFolderUrl + "/child", postParams3);

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");

        // fetch the JSON for the eacl to verify the settings.
        String getUrl = testFolderUrl + "/child.eacl.json";

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject jsonObject = parseJson(json);

        JsonObject aceObject = jsonObject.getJsonObject(testUserId);
        assertNotNull(aceObject);

        String principalString = aceObject.getString("principal");
        assertEquals(testUserId, principalString);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(1, privilegesObject.size());
        // allow privilege
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_ALL);
    }

    /**
     * Test for SLING-2600, Effective ACL servlet returns incorrect information
     */
    @Test
    public void testEffectiveAclMergeForUserSubsetOfPrivilegesDeniedOnChild2()
            throws IOException, JsonException, RepositoryException {
        testUserId = createTestUser();

        testFolderUrl = createTestFolder(
                null,
                "sling-tests",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"propOne\" : \"propOneValue\", \"child\" : { \"childPropOne\" : true } }");

        List<NameValuePair> postParams = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_ALL, PrivilegeValues.ALLOW)
                .build();
        addOrUpdateAce(testFolderUrl, postParams);

        List<NameValuePair> postParams3 = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_REMOVE_NODE, PrivilegeValues.DENY)
                .build();
        addOrUpdateAce(testFolderUrl + "/child", postParams3);

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");

        // fetch the JSON for the eacl to verify the settings.
        String getUrl = testFolderUrl + "/child.eacl.json";

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject jsonObject = parseJson(json);

        JsonObject aceObject = jsonObject.getJsonObject(testUserId);
        assertNotNull(aceObject);

        String principalString = aceObject.getString("principal");
        assertEquals(testUserId, principalString);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertTrue(privilegesObject.size() >= 11);
        // not there privileges
        assertPrivilege(privilegesObject, false, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_ALL);
        assertPrivilege(privilegesObject, false, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_WRITE);
        // allow privileges
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_READ);
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_READ_ACCESS_CONTROL);
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_MODIFY_ACCESS_CONTROL);
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_LOCK_MANAGEMENT);
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_VERSION_MANAGEMENT);
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_NODE_TYPE_MANAGEMENT);
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_RETENTION_MANAGEMENT);
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_LIFECYCLE_MANAGEMENT);
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_MODIFY_PROPERTIES);
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_ADD_CHILD_NODES);
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_REMOVE_CHILD_NODES);
        // deny privileges
        assertPrivilege(privilegesObject, true, PrivilegeValues.DENY, PrivilegeConstants.JCR_REMOVE_NODE);
    }

    /**
     * Test for SLING-2600, Effective ACL servlet returns incorrect information
     */
    @Test
    public void testEffectiveAclMergeForUserSupersetOfPrivilegesDeniedOnChild()
            throws IOException, JsonException, RepositoryException {
        testUserId = createTestUser();

        testFolderUrl = createTestFolder(
                null,
                "sling-tests",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"propOne\" : \"propOneValue\", \"child\" : { \"childPropOne\" : true } }");

        List<NameValuePair> postParams = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_WRITE, PrivilegeValues.ALLOW)
                .build();
        addOrUpdateAce(testFolderUrl, postParams);

        List<NameValuePair> postParams3 = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_ALL, PrivilegeValues.DENY)
                .build();
        addOrUpdateAce(testFolderUrl + "/child", postParams3);

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");

        // fetch the JSON for the eacl to verify the settings.
        String getUrl = testFolderUrl + "/child.eacl.json";

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject jsonObject = parseJson(json);

        JsonObject aceObject = jsonObject.getJsonObject(testUserId);
        assertNotNull(aceObject);

        String principalString = aceObject.getString("principal");
        assertEquals(testUserId, principalString);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(1, privilegesObject.size());
        assertPrivilege(privilegesObject, true, PrivilegeValues.DENY, PrivilegeConstants.JCR_ALL);
    }

    /**
     * Test for SLING-2600, Effective ACL servlet returns incorrect information
     */
    @Test
    public void testEffectiveAclMergeForUserSupersetOfPrivilegesDeniedOnChild2()
            throws IOException, JsonException, RepositoryException {
        testUserId = createTestUser();

        testFolderUrl = createTestFolder(
                null,
                "sling-tests",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"propOne\" : \"propOneValue\", \"child\" : { \"childPropOne\" : true } }");

        List<NameValuePair> postParams = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_MODIFY_PROPERTIES, PrivilegeValues.ALLOW)
                .build();
        addOrUpdateAce(testFolderUrl, postParams);

        List<NameValuePair> postParams3 = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_ALL, PrivilegeValues.DENY)
                .build();
        addOrUpdateAce(testFolderUrl + "/child", postParams3);

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");

        // fetch the JSON for the eacl to verify the settings.
        String getUrl = testFolderUrl + "/child.eacl.json";

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject jsonObject = parseJson(json);

        JsonObject aceObject = jsonObject.getJsonObject(testUserId);
        assertNotNull(aceObject);

        String principalString = aceObject.getString("principal");
        assertEquals(testUserId, principalString);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(1, privilegesObject.size());
        assertPrivilege(privilegesObject, true, PrivilegeValues.DENY, PrivilegeConstants.JCR_ALL);
    }

    /**
     * ACL servlet returns 404 when no read access rights permissions
     */
    @Test
    public void testNoAccessToDeclaredAclForUser() throws IOException, JsonException, RepositoryException {
        testUserId = createTestUser();
        testFolderUrl = createTestFolder(
                null,
                "sling-tests",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"child\" : { \"childPropOne\" : true } }");

        // 1. create an initial set of privileges
        List<NameValuePair> postParams = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_READ_ACCESS_CONTROL, PrivilegeValues.DENY)
                .build();
        addOrUpdateAce(testFolderUrl, postParams);

        Credentials creds = new UsernamePasswordCredentials(testUserId, "testPwd");

        // fetch the JSON for the ace to verify the settings.
        String getUrl = testFolderUrl + "/child.acl.json";
        // no declared access control entry returns a 404
        assertAuthenticatedHttpStatus(
                creds, getUrl, HttpServletResponse.SC_NOT_FOUND, "Did not expect an ace to be returned");
    }
}
