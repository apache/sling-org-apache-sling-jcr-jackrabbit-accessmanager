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
import java.util.ArrayList;
import java.util.List;

import javax.json.JsonException;
import javax.json.JsonObject;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.NameValuePair;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.message.BasicNameValuePair;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;

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
    public void testEffectiveAclForUser() throws IOException, JsonException {
        testUserId = createTestUser();
        testUserId2 = createTestUser();

        testFolderUrl = createTestFolder(null, "sling-tests",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"propOne\" : \"propOneValue\", \"child\" : { \"childPropOne\" : true } }");

        String postUrl = testFolderUrl + ".modifyAce.html";

        //1. create an initial set of privileges
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:write", "granted"));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId2));
        postParams.add(new BasicNameValuePair("privilege@jcr:write", "granted"));

        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId2));
        postParams.add(new BasicNameValuePair("privilege@jcr:lockManagement", "granted"));

        postUrl = testFolderUrl + "/child.modifyAce.html";
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);


        //fetch the JSON for the eacl to verify the settings.
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
        //allow privilege
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_WRITE);

        JsonObject aceObject2 = jsonObject.getJsonObject(testUserId2);
        assertNotNull(aceObject2);

        String principalString2 = aceObject2.getString("principal");
        assertEquals(testUserId2, principalString2);

        JsonObject privilegesObject2 = aceObject2.getJsonObject("privileges");
        assertNotNull(privilegesObject2);
        assertEquals(2, privilegesObject2.size());
        //allow privilege
        assertPrivilege(privilegesObject2, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_WRITE);
        assertPrivilege(privilegesObject2, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_LOCK_MANAGEMENT);
    }

    /**
     * Test for SLING-2600, Effective ACL servlet returns incorrect information
     */
    @Test
    public void testEffectiveAclMergeForUserReplacePrivilegeOnChild() throws IOException, JsonException {
        testUserId = createTestUser();

        testFolderUrl = createTestFolder(null, "sling-tests",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"propOne\" : \"propOneValue\", \"child\" : { \"childPropOne\" : true } }");

        String postUrl = testFolderUrl + ".modifyAce.html";

        //1. create an initial set of privileges
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:write", "denied"));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:write", "granted"));

        postUrl = testFolderUrl + "/child.modifyAce.html";
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);


        //fetch the JSON for the eacl to verify the settings.
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
        //allow privilege
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_WRITE);
    }

    /**
     * Test for SLING-2600, Effective ACL servlet returns incorrect information
     */
    @Test
    public void testEffectiveAclMergeForUserFewerPrivilegesGrantedOnChild() throws IOException, JsonException {
        testUserId = createTestUser();

        testFolderUrl = createTestFolder(null, "sling-tests",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"propOne\" : \"propOneValue\", \"child\" : { \"childPropOne\" : true } }");

        String postUrl = testFolderUrl + ".modifyAce.html";

        //1. create an initial set of privileges
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:all", "granted"));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:write", "granted"));

        postUrl = testFolderUrl + "/child.modifyAce.html";
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);


        //fetch the JSON for the eacl to verify the settings.
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
        //allow privilege
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_ALL);
    }

    /**
     * Test for SLING-2600, Effective ACL servlet returns incorrect information
     */
    @Test
    public void testEffectiveAclMergeForUserMorePrivilegesGrantedOnChild() throws IOException, JsonException {
        testUserId = createTestUser();

        testFolderUrl = createTestFolder(null, "sling-tests",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"propOne\" : \"propOneValue\", \"child\" : { \"childPropOne\" : true } }");

        String postUrl = testFolderUrl + ".modifyAce.html";

        //1. create an initial set of privileges
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:write", "granted"));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:all", "granted"));

        postUrl = testFolderUrl + "/child.modifyAce.html";
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);


        //fetch the JSON for the eacl to verify the settings.
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
        //allow privilege
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_ALL);
    }

    /**
     * Test for SLING-2600, Effective ACL servlet returns incorrect information
     */
    @Test
    public void testEffectiveAclMergeForUserSubsetOfPrivilegesDeniedOnChild2() throws IOException, JsonException {
        testUserId = createTestUser();

        testFolderUrl = createTestFolder(null, "sling-tests",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"propOne\" : \"propOneValue\", \"child\" : { \"childPropOne\" : true } }");

        String postUrl = testFolderUrl + ".modifyAce.html";

        //1. create an initial set of privileges
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:all", "granted"));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:removeNode", "denied"));

        postUrl = testFolderUrl + "/child.modifyAce.html";
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);


        //fetch the JSON for the eacl to verify the settings.
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
        //deny privileges
        assertPrivilege(privilegesObject, true, PrivilegeValues.DENY, PrivilegeConstants.JCR_REMOVE_NODE);
    }

    /**
     * Test for SLING-2600, Effective ACL servlet returns incorrect information
     */
    @Test
    public void testEffectiveAclMergeForUserSupersetOfPrivilegesDeniedOnChild() throws IOException, JsonException {
        testUserId = createTestUser();

        testFolderUrl = createTestFolder(null, "sling-tests",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"propOne\" : \"propOneValue\", \"child\" : { \"childPropOne\" : true } }");

        String postUrl = testFolderUrl + ".modifyAce.html";

        //1. create an initial set of privileges
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:write", "granted"));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:all", "denied"));

        postUrl = testFolderUrl + "/child.modifyAce.html";
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);


        //fetch the JSON for the eacl to verify the settings.
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
    public void testEffectiveAclMergeForUserSupersetOfPrivilegesDeniedOnChild2() throws IOException, JsonException {
        testUserId = createTestUser();

        testFolderUrl = createTestFolder(null, "sling-tests",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"propOne\" : \"propOneValue\", \"child\" : { \"childPropOne\" : true } }");

        String postUrl = testFolderUrl + ".modifyAce.html";

        //1. create an initial set of privileges
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:modifyProperties", "granted"));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:all", "denied"));

        postUrl = testFolderUrl + "/child.modifyAce.html";
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);


        //fetch the JSON for the eacl to verify the settings.
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
}
