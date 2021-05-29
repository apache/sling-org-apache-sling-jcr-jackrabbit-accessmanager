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
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.json.JsonArray;
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
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;

@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class AccessPrivilegesInfoIT extends AccessManagerClientTestSupport {

    @Override
    protected Option buildBundleResourcesBundle() throws IOException {
        final List<String> resourcePaths = Arrays.asList("/apps/nt/unstructured/privileges-info.json.esp");
        final String bundleResourcesHeader = String.join(",", resourcePaths);
        return buildBundleResourcesBundle(bundleResourcesHeader, resourcePaths);
    }

    /*
     * testuser granted read / denied write
     */
    @Test
    public void testDeniedWriteForUser() throws IOException, JsonException {
        testUserId = createTestUser();
        testFolderUrl = createTestFolder();

        //assign some privileges
        String postUrl = testFolderUrl + ".modifyAce.html";

        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:readAccessControl", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:write", "denied"));

        Credentials adminCreds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(adminCreds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        String getUrl = testFolderUrl + ".privileges-info.json";

        //fetch the JSON for the test page to verify the settings.
        Credentials testUserCreds = new UsernamePasswordCredentials(testUserId, "testPwd");

        String json = getAuthenticatedContent(testUserCreds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject jsonObj = parseJson(json);
        assertNotNull(jsonObj);

        assertEquals(false, jsonObj.getBoolean("canAddChildren"));
        assertEquals(false, jsonObj.getBoolean("canDeleteChildren"));
        assertEquals(false, jsonObj.getBoolean("canDelete"));
        assertEquals(false, jsonObj.getBoolean("canModifyProperties"));
        assertEquals(true, jsonObj.getBoolean("canReadAccessControl"));
        assertEquals(false, jsonObj.getBoolean("canModifyAccessControl"));
    }

    /*
     * testuser granted read / granted write
     */
    @Test
    public void testGrantedWriteForUser() throws IOException, JsonException {
        testUserId = createTestUser();
        testFolderUrl = createTestFolder();

        //assign some privileges
        String postUrl = testFolderUrl + ".modifyAce.html";

        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:write", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:readAccessControl", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:modifyAccessControl", "granted"));

        Credentials adminCreds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(adminCreds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        String getUrl = testFolderUrl + ".privileges-info.json";

        //fetch the JSON for the test page to verify the settings.
        Credentials testUserCreds = new UsernamePasswordCredentials(testUserId, "testPwd");

        String json = getAuthenticatedContent(testUserCreds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject jsonObj = parseJson(json);

        assertEquals(true, jsonObj.getBoolean("canAddChildren"));
        assertEquals(true, jsonObj.getBoolean("canDeleteChildren"));
        //the parent node must also have jcr:removeChildren granted for 'canDelete' to be true
        assertEquals(false, jsonObj.getBoolean("canDelete"));
        assertEquals(true, jsonObj.getBoolean("canModifyProperties"));
        assertEquals(true, jsonObj.getBoolean("canReadAccessControl"));
        assertEquals(true, jsonObj.getBoolean("canModifyAccessControl"));

        //add a child node to verify the 'canDelete' use case
        String parentPath = testFolderUrl.substring(baseServerUri.toString().length());
        String childFolderUrl = createTestFolder(parentPath, "testFolder");
        String childPostUrl = childFolderUrl + ".modifyAce.html";

        postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:removeNode", "granted"));
        assertAuthenticatedPostStatus(adminCreds, childPostUrl, HttpServletResponse.SC_OK, postParams, null);

        String childGetUrl = childFolderUrl + ".privileges-info.json";
        String childJson = getAuthenticatedContent(testUserCreds, childGetUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(childJson);
        JsonObject childJsonObj = parseJson(childJson);
        assertEquals(true, childJsonObj.getBoolean("canDelete"));
    }

    /*
     * group testuser granted read / denied write
     */
    @Test
    public void testDeniedWriteForGroup() throws IOException, JsonException {
        testGroupId = createTestGroup();
        testUserId = createTestUser();
        testFolderUrl = createTestFolder();

        Credentials adminCreds = new UsernamePasswordCredentials("admin", "admin");

        //add testUserId to testGroup
        String groupPostUrl = String.format("%s/system/userManager/group/%s.update.html", baseServerUri, testGroupId);
        List<NameValuePair> groupPostParams = new ArrayList<>();
        groupPostParams.add(new BasicNameValuePair(":member", testUserId));
        assertAuthenticatedPostStatus(adminCreds, groupPostUrl, HttpServletResponse.SC_OK, groupPostParams, null);

        //assign some privileges
        String postUrl = testFolderUrl + ".modifyAce.html";

        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testGroupId));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:readAccessControl", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:write", "denied"));

        assertAuthenticatedPostStatus(adminCreds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        String getUrl = testFolderUrl + ".privileges-info.json";

        //fetch the JSON for the test page to verify the settings.
        Credentials testUserCreds = new UsernamePasswordCredentials(testUserId, "testPwd");

        String json = getAuthenticatedContent(testUserCreds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject jsonObj = parseJson(json);

        assertEquals(false, jsonObj.getBoolean("canAddChildren"));
        assertEquals(false, jsonObj.getBoolean("canDeleteChildren"));
        assertEquals(false, jsonObj.getBoolean("canDelete"));
        assertEquals(false, jsonObj.getBoolean("canModifyProperties"));
        assertEquals(true, jsonObj.getBoolean("canReadAccessControl"));
        assertEquals(false, jsonObj.getBoolean("canModifyAccessControl"));
    }

    /*
     * group testuser granted read / granted write
     */
    @Test
    public void testGrantedWriteForGroup() throws IOException, JsonException {
        testGroupId = createTestGroup();
        testUserId = createTestUser();
        testFolderUrl = createTestFolder();

        Credentials adminCreds = new UsernamePasswordCredentials("admin", "admin");

        //add testUserId to testGroup
        String groupPostUrl = String.format("%s/system/userManager/group/%s.update.html", baseServerUri, testGroupId);
        List<NameValuePair> groupPostParams = new ArrayList<>();
        groupPostParams.add(new BasicNameValuePair(":member", testUserId));
        assertAuthenticatedPostStatus(adminCreds, groupPostUrl, HttpServletResponse.SC_OK, groupPostParams, null);

        //assign some privileges
        String postUrl = testFolderUrl + ".modifyAce.html";

        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testGroupId));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:write", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:readAccessControl", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:modifyAccessControl", "granted"));

        assertAuthenticatedPostStatus(adminCreds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        String getUrl = testFolderUrl + ".privileges-info.json";

        //fetch the JSON for the test page to verify the settings.
        Credentials testUserCreds = new UsernamePasswordCredentials(testUserId, "testPwd");

        String json = getAuthenticatedContent(testUserCreds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject jsonObj = parseJson(json);

        assertEquals(true, jsonObj.getBoolean("canAddChildren"));
        assertEquals(true, jsonObj.getBoolean("canDeleteChildren"));
        //the parent node must also have jcr:removeChildren granted for 'canDelete' to be true
        assertEquals(false, jsonObj.getBoolean("canDelete"));
        assertEquals(true, jsonObj.getBoolean("canModifyProperties"));
        assertEquals(true, jsonObj.getBoolean("canReadAccessControl"));
        assertEquals(true, jsonObj.getBoolean("canModifyAccessControl"));

        //add a child node to verify the 'canDelete' use case
        String parentPath = testFolderUrl.substring(baseServerUri.toString().length());
        String childFolderUrl = createTestFolder(parentPath, "testFolder");
        String childPostUrl = childFolderUrl + ".modifyAce.html";

        postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testGroupId));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:removeNode", "granted"));
        assertAuthenticatedPostStatus(adminCreds, childPostUrl, HttpServletResponse.SC_OK, postParams, null);

        String childGetUrl = childFolderUrl + ".privileges-info.json";
        String childJson = getAuthenticatedContent(testUserCreds, childGetUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(childJson);
        JsonObject childJsonObj = parseJson(childJson);
        assertEquals(true, childJsonObj.getBoolean("canDelete"));
    }


    /**
     * Test the fix for SLING-1090
     */
    @Test
    public void testSLING1090() throws IOException {
        testUserId = createTestUser();

        //grant jcr: removeChildNodes to the root node
        ArrayList<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:removeChildNodes", "granted"));
        Credentials adminCreds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(adminCreds, String.format("%s/.modifyAce.html", baseServerUri), HttpServletResponse.SC_OK, postParams, null);

        //create a node as a child of the root folder
        testFolderUrl = createTestFolder("/", "testSLING1090");
        String postUrl = testFolderUrl + ".modifyAce.html";

        //grant jcr:removeNode to the test node
        postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:removeNode", "granted"));
        assertAuthenticatedPostStatus(adminCreds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        //fetch the JSON for the test page to verify the settings.
        String getUrl = testFolderUrl + ".privileges-info.json";
        Credentials testUserCreds = new UsernamePasswordCredentials(testUserId, "testPwd");
        String json = getAuthenticatedContent(testUserCreds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject jsonObj = parseJson(json);
        assertEquals(true, jsonObj.getBoolean("canDelete"));
    }

    /**
     * Test for SLING-7835, PrivilegesInfo#getDeclaredAccessRights returns incorrect information
     */
    @Test
    public void testDeclaredAclForUser() throws IOException, JsonException {
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
        String getUrl = testFolderUrl + "/child.privileges-info.json";
        Credentials testUserCreds = new UsernamePasswordCredentials("admin", "admin");
        String json = getAuthenticatedContent(testUserCreds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject jsonObject = parseJson(json);
        jsonObject = jsonObject.getJsonObject("declaredAccessRights");

        assertNull(jsonObject.get(testUserId));

        JsonObject aceObject2 = jsonObject.getJsonObject(testUserId2);
        assertNotNull(aceObject2);

        JsonArray grantedArray2 = aceObject2.getJsonArray("granted");
        assertNotNull(grantedArray2);
        assertEquals(1, grantedArray2.size());
        Set<String> grantedPrivilegeNames2 = new HashSet<>();
        for (int i=0; i < grantedArray2.size(); i++) {
            grantedPrivilegeNames2.add(grantedArray2.getString(i));
        }
        assertPrivilege(grantedPrivilegeNames2, true, "jcr:lockManagement");

        JsonArray deniedArray2 = aceObject2.getJsonArray("denied");
        assertNotNull(deniedArray2);
        assertEquals(0, deniedArray2.size());


        getUrl = testFolderUrl + ".privileges-info.json";
        json = getAuthenticatedContent(testUserCreds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        jsonObject = parseJson(json);
        jsonObject = jsonObject.getJsonObject("declaredAccessRights");

        JsonObject aceObject = jsonObject.getJsonObject(testUserId);
        assertNotNull(aceObject);

        JsonArray grantedArray = aceObject.getJsonArray("granted");
        assertNotNull(grantedArray);
        assertEquals(1, grantedArray.size());
        Set<String> grantedPrivilegeNames = new HashSet<>();
        for (int i=0; i < grantedArray.size(); i++) {
            grantedPrivilegeNames.add(grantedArray.getString(i));
        }
        assertPrivilege(grantedPrivilegeNames,true, PrivilegeConstants.JCR_WRITE);

        JsonArray deniedArray = aceObject.getJsonArray("denied");
        assertNotNull(deniedArray);
        assertEquals(0, deniedArray.size());

        aceObject2 = jsonObject.getJsonObject(testUserId2);
        assertNotNull(aceObject2);

        grantedArray2 = aceObject2.getJsonArray("granted");
        assertNotNull(grantedArray2);
        assertEquals(1, grantedArray2.size());
        grantedPrivilegeNames2 = new HashSet<>();
        for (int i=0; i < grantedArray2.size(); i++) {
            grantedPrivilegeNames2.add(grantedArray2.getString(i));
        }
        assertPrivilege(grantedPrivilegeNames2, true, PrivilegeConstants.JCR_WRITE);

        deniedArray2 = aceObject2.getJsonArray("denied");
        assertNotNull(deniedArray2);
        assertEquals(0, deniedArray2.size());
    }

    /**
     * Test for SLING-7835, PrivilegesInfo#getEffectiveAccessRights returns incorrect information
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
        String getUrl = testFolderUrl + "/child.privileges-info.json";
        Credentials testUserCreds = new UsernamePasswordCredentials("admin", "admin");
        String json = getAuthenticatedContent(testUserCreds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject jsonObject = parseJson(json);
        jsonObject = jsonObject.getJsonObject("effectiveAccessRights");

        JsonObject aceObject = jsonObject.getJsonObject(testUserId);
        assertNotNull(aceObject);

        JsonArray grantedArray = aceObject.getJsonArray("granted");
        assertNotNull(grantedArray);
        assertEquals(1, grantedArray.size());
        Set<String> grantedPrivilegeNames = new HashSet<>();
        for (int i=0; i < grantedArray.size(); i++) {
            grantedPrivilegeNames.add(grantedArray.getString(i));
        }
        assertPrivilege(grantedPrivilegeNames,true, PrivilegeConstants.JCR_WRITE);

        JsonArray deniedArray = aceObject.getJsonArray("denied");
        assertNotNull(deniedArray);
        assertEquals(0, deniedArray.size());

        JsonObject aceObject2 = jsonObject.getJsonObject(testUserId2);
        assertNotNull(aceObject2);

        JsonArray grantedArray2 = aceObject2.getJsonArray("granted");
        assertNotNull(grantedArray2);
        assertEquals(2, grantedArray2.size());
        Set<String> grantedPrivilegeNames2 = new HashSet<>();
        for (int i=0; i < grantedArray2.size(); i++) {
            grantedPrivilegeNames2.add(grantedArray2.getString(i));
        }
        assertPrivilege(grantedPrivilegeNames2, true, PrivilegeConstants.JCR_WRITE);
        assertPrivilege(grantedPrivilegeNames2, true, "jcr:lockManagement");

        JsonArray deniedArray2 = aceObject2.getJsonArray("denied");
        assertNotNull(deniedArray2);
        assertEquals(0, deniedArray2.size());
    }

}
