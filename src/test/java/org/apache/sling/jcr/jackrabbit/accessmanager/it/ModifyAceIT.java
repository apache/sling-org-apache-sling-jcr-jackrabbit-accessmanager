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
import java.lang.reflect.Array;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.json.JsonArray;
import javax.json.JsonException;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.json.JsonValue.ValueType;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.NameValuePair;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.message.BasicNameValuePair;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.sling.servlets.post.JSONResponse;
import org.apache.sling.servlets.post.PostResponseCreator;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;
import org.osgi.framework.Bundle;
import org.osgi.framework.FrameworkUtil;
import org.osgi.framework.ServiceRegistration;

/**
 * Tests for the 'modifyAce' Sling Post Operation
 */
@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class ModifyAceIT extends AccessManagerClientTestSupport {

    private ServiceRegistration<PostResponseCreator> serviceReg;

    @Before
    @Override
    public void before() throws IOException, URISyntaxException {
        Bundle bundle = FrameworkUtil.getBundle(getClass());
        Dictionary<String, Object> props = new Hashtable<>(); // NOSONAR
        serviceReg = bundle.getBundleContext().registerService(PostResponseCreator.class,
                new CustomPostResponseCreatorImpl(), props);

        super.before();
    }

    @After
    @Override
    public void after() throws IOException {
        if (serviceReg != null) {
            serviceReg.unregister();
        }

        super.after();
    }

    @Test
    public void testModifyAceForUser() throws IOException, JsonException {
        testUserId = createTestUser();

        testFolderUrl = createTestFolder();

        String postUrl = testFolderUrl + ".modifyAce.html";

        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:write", "denied"));
        postParams.add(new BasicNameValuePair("privilege@jcr:modifyAccessControl", "bogus")); //invalid value should be ignored.

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);


        //fetch the JSON for the acl to verify the settings.
        String getUrl = testFolderUrl + ".acl.json";

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject jsonObject = parseJson(json);
        assertEquals(1, jsonObject.size());

        JsonObject aceObject = jsonObject.getJsonObject(testUserId);
        assertNotNull(aceObject);

        String principalString = aceObject.getString("principal");
        assertEquals(testUserId, principalString);

        int order = aceObject.getInt("order");
        assertEquals(0, order);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(2, privilegesObject.size());
        //allow privileges
        assertPrivilege(privilegesObject, true, true, PrivilegeConstants.JCR_READ);
        //deny privileges
        assertPrivilege(privilegesObject, true, false, PrivilegeConstants.JCR_WRITE);
    }

    /**
     * Test for SLING-7831
     */
    @Test
    public void testModifyAceCustomPostResponse() throws IOException, JsonException {
        testUserId = createTestUser();

        testFolderUrl = createTestFolder();

        String postUrl = testFolderUrl + ".modifyAce.html";

        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":responseType", "custom"));
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "granted"));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String content = getAuthenticatedPostContent(creds, postUrl, CONTENT_TYPE_HTML, postParams, HttpServletResponse.SC_OK);
        assertEquals("Thanks!", content); //verify that the content matches the custom response
    }

    @Test
    public void testModifyAceForGroup() throws IOException, JsonException {
        testGroupId = createTestGroup();

        testFolderUrl = createTestFolder();

        String postUrl = testFolderUrl + ".modifyAce.html";

        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testGroupId));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:write", "denied"));
        postParams.add(new BasicNameValuePair("privilege@jcr:modifyAccessControl", "bogus")); //invalid value should be ignored.

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);


        //fetch the JSON for the acl to verify the settings.
        String getUrl = testFolderUrl + ".acl.json";

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject jsonObject = parseJson(json);
        assertEquals(1, jsonObject.size());

        JsonObject aceObject = jsonObject.getJsonObject(testGroupId);
        assertNotNull(aceObject);

        int order = aceObject.getInt("order");
        assertEquals(0, order);

        String principalString = aceObject.getString("principal");
        assertEquals(testGroupId, principalString);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(2, privilegesObject.size());
        //allow privileges
        assertPrivilege(privilegesObject, true, true, PrivilegeConstants.JCR_READ);
        //deny privileges
        assertPrivilege(privilegesObject, true, false, PrivilegeConstants.JCR_WRITE);
    }

    /**
     * Test for SLING-997, preserve privileges that were not posted with the modifyAce
     * request.
     */
    @Test
    public void testMergeAceForUser() throws IOException, JsonException {
        testUserId = createTestUser();
        testFolderUrl = createTestFolder();

        String postUrl = testFolderUrl + ".modifyAce.html";

        //1. create an initial set of privileges
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:readAccessControl", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:addChildNodes", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:modifyAccessControl", "denied"));
        postParams.add(new BasicNameValuePair("privilege@jcr:removeChildNodes", "denied"));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        //fetch the JSON for the acl to verify the settings.
        String getUrl = testFolderUrl + ".acl.json";

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject jsonObject = parseJson(json);
        assertEquals(1, jsonObject.size());

        JsonObject aceObject = jsonObject.getJsonObject(testUserId);
        assertNotNull(aceObject);

        String principalString = aceObject.getString("principal");
        assertEquals(testUserId, principalString);

        int order = aceObject.getInt("order");
        assertEquals(0, order);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(5, privilegesObject.size());
        //allow privileges
        assertPrivilege(privilegesObject, true, true, PrivilegeConstants.JCR_READ);
        assertPrivilege(privilegesObject, true, true, PrivilegeConstants.JCR_READ_ACCESS_CONTROL);
        assertPrivilege(privilegesObject, true, true, PrivilegeConstants.JCR_ADD_CHILD_NODES);
        //deny privileges
        assertPrivilege(privilegesObject, true, false, PrivilegeConstants.JCR_MODIFY_ACCESS_CONTROL);
        assertPrivilege(privilegesObject, true, false, PrivilegeConstants.JCR_REMOVE_CHILD_NODES);



        //2. post a new set of privileges to merge with the existing privileges
        List<NameValuePair> postParams2 = new ArrayList<>();
        postParams2.add(new BasicNameValuePair("principalId", testUserId));
        //jcr:read and jcr:addChildNodes are not posted, so they should remain in the granted ACE
        postParams2.add(new BasicNameValuePair("privilege@jcr:readAccessControl", "none")); //clear the existing privilege
        postParams2.add(new BasicNameValuePair("privilege@jcr:modifyProperties", "granted")); //add a new privilege
        //jcr:modifyAccessControl is not posted, so it should remain in the denied ACE
        postParams2.add(new BasicNameValuePair("privilege@jcr:modifyAccessControl", "denied")); //deny the modifyAccessControl privilege
        postParams2.add(new BasicNameValuePair("privilege@jcr:removeChildNodes", "none")); //clear the existing privilege
        postParams2.add(new BasicNameValuePair("privilege@jcr:removeNode", "denied")); //deny a new privilege

        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams2, null);


        //fetch the JSON for the acl to verify the settings.
        String json2 = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json2);
        JsonObject jsonObject2 = parseJson(json2);
        assertEquals(1, jsonObject2.size());

        JsonObject aceObject2 = jsonObject2.getJsonObject(testUserId);
        assertNotNull(aceObject2);

        String principalString2 = aceObject2.getString("principal");
        assertEquals(testUserId, principalString2);

        JsonObject privilegesObject2 = aceObject2.getJsonObject("privileges");
        assertNotNull(privilegesObject2);
        assertEquals(5, privilegesObject2.size());
        //allow privileges
        assertPrivilege(privilegesObject2, true, true, PrivilegeConstants.JCR_READ);
        assertPrivilege(privilegesObject2, true, true, PrivilegeConstants.JCR_ADD_CHILD_NODES);
        assertPrivilege(privilegesObject2, true, true, PrivilegeConstants.JCR_MODIFY_PROPERTIES);
        //deny privileges
        assertPrivilege(privilegesObject2, true, false, PrivilegeConstants.JCR_MODIFY_ACCESS_CONTROL);
        assertPrivilege(privilegesObject2, true, false, PrivilegeConstants.JCR_REMOVE_NODE);
    }


    /**
     * Test for SLING-997, preserve privileges that were not posted with the modifyAce
     * request.
     */
    @Test
    public void testMergeAceForUserSplitAggregatePrincipal() throws IOException, JsonException {
        testUserId = createTestUser();
        testFolderUrl = createTestFolder();

        String postUrl = testFolderUrl + ".modifyAce.html";

        //1. create an initial set of privileges
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:write", "denied"));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        //fetch the JSON for the acl to verify the settings.
        String getUrl = testFolderUrl + ".acl.json";

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);

        JsonObject jsonObject = parseJson(json);
        assertEquals(1, jsonObject.size());

        JsonObject aceObject = jsonObject.getJsonObject(testUserId);
        assertNotNull(aceObject);

        assertEquals(testUserId, aceObject.getString("principal"));

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(2, privilegesObject.size());
        //allow privileges
        assertPrivilege(privilegesObject, true, true, PrivilegeConstants.JCR_READ);
        //deny privileges
        assertPrivilege(privilegesObject, true, false, PrivilegeConstants.JCR_WRITE);



        //2. post a new set of privileges to merge with the existing privileges
        List<NameValuePair> postParams2 = new ArrayList<>();
        postParams2.add(new BasicNameValuePair("principalId", testUserId));
        //jcr:read is not posted, so it should remain in the granted ACE
        postParams2.add(new BasicNameValuePair("privilege@jcr:modifyProperties", "granted")); //add a new privilege
        //jcr:write is not posted, but one of the aggregate privileges is now granted, so the aggregate priviledge should be disagreaged into
        //  the remaining denied privileges in the denied ACE

        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams2, null);


        //fetch the JSON for the acl to verify the settings.
        String json2 = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json2);

        JsonObject jsonObject2 = parseJson(json2);
        assertEquals(1, jsonObject2.size());

        JsonObject aceObject2 = jsonObject2.getJsonObject(testUserId);
        assertNotNull(aceObject2);

        assertEquals(testUserId, aceObject2.getString("principal"));

        JsonObject privilegesObject2 = aceObject2.getJsonObject("privileges");
        assertNotNull(privilegesObject2);
        assertEquals(5, privilegesObject2.size());
        //allow privileges
        assertPrivilege(privilegesObject2, true, true, PrivilegeConstants.JCR_READ);
        assertPrivilege(privilegesObject2, true, true, PrivilegeConstants.JCR_MODIFY_PROPERTIES);
        //deny privileges
        assertPrivilege(privilegesObject2, true, false, PrivilegeConstants.JCR_ADD_CHILD_NODES);
        assertPrivilege(privilegesObject2, true, false, PrivilegeConstants.JCR_REMOVE_NODE);
        assertPrivilege(privilegesObject2, true, false, PrivilegeConstants.JCR_REMOVE_CHILD_NODES);
    }

    /**
     * Test for SLING-997, preserve privileges that were not posted with the modifyAce
     * request.
     */
    @Test
    public void testMergeAceForUserCombineAggregatePrivilege() throws IOException, JsonException {
        testUserId = createTestUser();
        testFolderUrl = createTestFolder();

        String postUrl = testFolderUrl + ".modifyAce.html";

        //1. create an initial set of privileges
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:removeNode", "denied"));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        //fetch the JSON for the acl to verify the settings.
        String getUrl = testFolderUrl + ".acl.json";

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);

        JsonObject jsonObject = parseJson(json);
        assertEquals(1, jsonObject.size());

        JsonObject aceObject = jsonObject.getJsonObject(testUserId);
        assertNotNull(aceObject);

        assertEquals(testUserId, aceObject.getString("principal"));

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(2, privilegesObject.size());
        //allow privileges
        assertPrivilege(privilegesObject, true, true, PrivilegeConstants.JCR_READ);
        //deny privileges
        assertPrivilege(privilegesObject, true, false, PrivilegeConstants.JCR_REMOVE_NODE);



        //2. post a new set of privileges to merge with the existing privileges
        List<NameValuePair> postParams2 = new ArrayList<>();
        postParams2.add(new BasicNameValuePair("principalId", testUserId));
        //jcr:read is not posted, so it should remain in the granted ACE

        //deny the full jcr:write aggregate privilege, which should merge with the
        //existing part.
        postParams2.add(new BasicNameValuePair("privilege@jcr:write", "denied")); //add a new privilege

        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams2, null);


        //fetch the JSON for the acl to verify the settings.
        String json2 = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json2);

        JsonObject jsonObject2 = parseJson(json2);
        assertEquals(1, jsonObject2.size());

        JsonObject aceObject2 = jsonObject2.getJsonObject(testUserId);
        assertNotNull(aceObject2);

        assertEquals(testUserId, aceObject2.getString("principal"));

        JsonObject privilegesObject2 = aceObject2.getJsonObject("privileges");
        assertNotNull(privilegesObject2);
        assertEquals(2, privilegesObject2.size());
        //allow privileges
        assertPrivilege(privilegesObject2, true, true, PrivilegeConstants.JCR_READ);
        //deny privileges
        assertPrivilege(privilegesObject2, true, false, PrivilegeConstants.JCR_WRITE);
    }


    /**
     * Test ACE update with a deny privilege for an ACE that already contains
     * a grant privilege
     */
    @Test
    public void testMergeAceForUserDenyPrivilegeAfterGrantPrivilege() throws IOException, JsonException {
        testUserId = createTestUser();
        testFolderUrl = createTestFolder();

        String postUrl = testFolderUrl + ".modifyAce.html";

        //1. create an initial set of privileges
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:write", "granted"));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        //fetch the JSON for the acl to verify the settings.
        String getUrl = testFolderUrl + ".acl.json";

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);

        JsonObject jsonObject = parseJson(json);
        assertEquals(1, jsonObject.size());

        JsonObject aceObject = jsonObject.getJsonObject(testUserId);
        assertNotNull(aceObject);

        assertEquals(testUserId, aceObject.getString("principal"));

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(1, privilegesObject.size());
        //allow privileges
        assertPrivilege(privilegesObject, true, true, PrivilegeConstants.JCR_WRITE);


        //2. post a new set of privileges to merge with the existing privileges
        List<NameValuePair> postParams2 = new ArrayList<>();
        postParams2.add(new BasicNameValuePair("principalId", testUserId));
        //jcr:write is not posted, so it should remain in the granted ACE

        //deny the jcr:nodeTypeManagement privilege, which should merge with the
        //existing ACE.
        postParams2.add(new BasicNameValuePair("privilege@jcr:nodeTypeManagement", "denied")); //add a new privilege

        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams2, null);


        //fetch the JSON for the acl to verify the settings.
        String json2 = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json2);

        JsonObject jsonObject2 = parseJson(json2);
        assertEquals(1, jsonObject2.size());

        JsonObject aceObject2 = jsonObject2.getJsonObject(testUserId);
        assertNotNull(aceObject2);

        assertEquals(testUserId, aceObject2.getString("principal"));

        JsonObject privilegesObject2 = aceObject2.getJsonObject("privileges");
        assertNotNull(privilegesObject2);
        assertEquals(2, privilegesObject2.size());
        //allow privileges
        assertPrivilege(privilegesObject2, true, true, PrivilegeConstants.JCR_WRITE);
        //deny privileges
        assertPrivilege(privilegesObject2, true, false, PrivilegeConstants.JCR_NODE_TYPE_MANAGEMENT);
    }



    /**
     * Test to verify adding an ACE in the first position of
     * the ACL
     */
    @Test
    public void testAddAceOrderByFirst() throws IOException, JsonException {
        createAceOrderTestFolderWithOneAce();

        testGroupId = createTestGroup();

        addOrUpdateAce(testFolderUrl, testGroupId, true, "first");

        //fetch the JSON for the acl to verify the settings.
        String getUrl = testFolderUrl + ".acl.json";

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);

        JsonObject jsonObject = parseJson(json);
        assertEquals(2, jsonObject.size());

        JsonObject group = jsonObject.getJsonObject(testGroupId);
        assertNotNull(group);
        assertEquals(testGroupId, group.getString("principal"));
                assertEquals(0, group.getInt("order"));
        JsonObject user =  jsonObject.getJsonObject(testUserId);
                assertNotNull(user);
                assertEquals(testUserId, user.getString("principal"));
                assertEquals(1, user.getInt("order"));
    }

    /**
     * Test to verify adding an ACE at the end
     * the ACL
     */
    @Test
    public void testAddAceOrderByLast() throws IOException, JsonException {
        createAceOrderTestFolderWithOneAce();

        testGroupId = createTestGroup();

        addOrUpdateAce(testFolderUrl, testGroupId, true, "last");

        //fetch the JSON for the acl to verify the settings.
        String getUrl = testFolderUrl + ".acl.json";

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);

        JsonObject jsonObject = parseJson(json);
        assertEquals(2, jsonObject.size());

                JsonObject user =  jsonObject.getJsonObject(testUserId);
                assertNotNull(user);
                assertEquals(testUserId, user.getString("principal"));
                assertEquals(0, user.getInt("order"));
                JsonObject group = jsonObject.getJsonObject(testGroupId);
                assertNotNull(group);
                assertEquals(testGroupId, group.getString("principal"));
                assertEquals(1, group.getInt("order"));

    }

    /**
     * Test to verify adding an ACE before an existing ACE
     * the ACL
     */
    @Test
    public void testAddAceOrderByBefore() throws IOException, JsonException {
        createAceOrderTestFolderWithOneAce();

        testGroupId = createTestGroup();

        addOrUpdateAce(testFolderUrl, testGroupId, true, "before " + testUserId);

        //fetch the JSON for the acl to verify the settings.
        String getUrl = testFolderUrl + ".acl.json";

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);


                JsonObject jsonObject = parseJson(json);
                assertEquals(2, jsonObject.size());


                JsonObject group = jsonObject.getJsonObject(testGroupId);
                assertNotNull(group);
                assertEquals(testGroupId, group.getString("principal"));
                assertEquals(0, group.getInt("order"));
                JsonObject user =  jsonObject.getJsonObject(testUserId);
                assertNotNull(user);
                assertEquals(testUserId, user.getString("principal"));
                assertEquals(1, user.getInt("order"));

    }

    /**
     * Test to verify adding an ACE after an existing ACE
     * the ACL
     */
    @Test
    public void testAddAceOrderByAfter() throws IOException, JsonException {
        createAceOrderTestFolderWithOneAce();

        testGroupId = createTestGroup();

        addOrUpdateAce(testFolderUrl, testGroupId, true, "after " + testUserId);

        //fetch the JSON for the acl to verify the settings.
        String getUrl = testFolderUrl + ".acl.json";

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);

                JsonObject jsonObject = parseJson(json);
                assertEquals(2, jsonObject.size());

                JsonObject user =  jsonObject.getJsonObject(testUserId);
                assertNotNull(user);
                assertEquals(testUserId, user.getString("principal"));
                assertEquals(0, user.getInt("order"));
                JsonObject group = jsonObject.getJsonObject(testGroupId);
                assertNotNull(group);
                assertEquals(testGroupId, group.getString("principal"));
                assertEquals(1, group.getInt("order"));

    }

    /**
     * Test to verify adding an ACE at a specific index inside
     * the ACL
     */
    @Test
    public void testAddAceOrderByNumeric() throws IOException, JsonException {
        createAceOrderTestFolderWithOneAce();

        testGroupId = createTestGroup();
        addOrUpdateAce(testFolderUrl, testGroupId, true, "0");

        //fetch the JSON for the acl to verify the settings.
        String getUrl = testFolderUrl + ".acl.json";

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);


                JsonObject jsonObject = parseJson(json);
                assertEquals(2, jsonObject.size());

                JsonObject group = jsonObject.getJsonObject(testGroupId);
                assertNotNull(group);
                assertEquals(testGroupId, group.getString("principal"));
                assertEquals(0, group.getInt("order"));

                JsonObject user =  jsonObject.getJsonObject(testUserId);
                assertNotNull(user);
                assertEquals(testUserId, user.getString("principal"));
                assertEquals(1, user.getInt("order"));



        //add another principal between the testGroupId and testUserId
        testUserId2 = createTestUser();
        addOrUpdateAce(testFolderUrl, testUserId2, true, "1");

        String json2 = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json2);

                JsonObject jsonObject2 = parseJson(json2);
                assertEquals(3, jsonObject2.size());

                JsonObject group2 = jsonObject2.getJsonObject(testGroupId);
                assertNotNull(group2);
                assertEquals(testGroupId, group2.getString("principal"));
                assertEquals(0, group2.getInt("order"));

                JsonObject user3 =  jsonObject2.getJsonObject(testUserId2);
                assertNotNull(user3);
                assertEquals(testUserId2, user3.getString("principal"));
                assertEquals(1, user3.getInt("order"));

                JsonObject user2 =  jsonObject2.getJsonObject(testUserId);
                assertNotNull(user2);
                assertEquals(testUserId, user2.getString("principal"));
                assertEquals(2, user2.getInt("order"));

    }

    /**
     * Test to make sure modifying an existing ace without changing the order
     * leaves the ACE in the same position in the ACL
     */
    @Test
    public void testUpdateAcePreservePosition() throws IOException, JsonException {
        createAceOrderTestFolderWithOneAce();

        testGroupId = createTestGroup();

        addOrUpdateAce(testFolderUrl, testGroupId, true, "first");

        //update the ace to make sure the update does not change the ACE order
        addOrUpdateAce(testFolderUrl, testGroupId, false, null);


        //fetch the JSON for the acl to verify the settings.
        String getUrl = testFolderUrl + ".acl.json";

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);

                JsonObject jsonObject = parseJson(json);
                assertEquals(2, jsonObject.size());

                JsonObject group = jsonObject.getJsonObject(testGroupId);
                assertNotNull(group);
                assertEquals(testGroupId, group.getString("principal"));
                assertEquals(0, group.getInt("order"));
                JsonObject user =  jsonObject.getJsonObject(testUserId);
                assertNotNull(user);
                assertEquals(testUserId, user.getString("principal"));
                assertEquals(1, user.getInt("order"));

    }


    /**
     * Helper to create a test folder with a single ACE pre-created
     */
    private void createAceOrderTestFolderWithOneAce() throws IOException, JsonException {
        testUserId = createTestUser();

        testFolderUrl = createTestFolder();

        addOrUpdateAce(testFolderUrl, testUserId, true, null);

        //fetch the JSON for the acl to verify the settings.
        String getUrl = testFolderUrl + ".acl.json";

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);

                JsonObject jsonObject = parseJson(json);
                assertEquals(1, jsonObject.size());

                JsonObject user = jsonObject.getJsonObject(testUserId);
                assertNotNull(user);
                assertEquals(testUserId, user.getString("principal"));
                assertEquals(0, user.getInt("order"));

    }

    /**
     * Helper to add or update an ace for testing
     */
    private void addOrUpdateAce(String folderUrl, String principalId, boolean readGranted, String order) throws IOException, JsonException {
        addOrUpdateAce(folderUrl, principalId, readGranted, order, null);
    }
    private void addOrUpdateAce(String folderUrl, String principalId, boolean readGranted, String order, Map<String, Object> restrictions) throws IOException, JsonException {
        String postUrl = folderUrl + ".modifyAce.html";

        //1. create an initial set of privileges
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", principalId));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", readGranted ? "granted" : "denied"));
        postParams.add(new BasicNameValuePair("privilege@jcr:write", "denied"));
        if (order != null) {
            postParams.add(new BasicNameValuePair("order", order));
        }
        if (restrictions != null) {
            Set<Entry<String, Object>> entrySet = restrictions.entrySet();
            for (Entry<String, Object> entry : entrySet) {
                Object value = entry.getValue();
                if (value != null) {
                    String rname = entry.getKey();
                    String paramName = String.format("restriction@%s", rname);

                    if (value.getClass().isArray()) {
                        int length = Array.getLength(value);
                        for (int i=0; i < length; i++) {
                            Object rvalue = Array.get(value, i);
                            if (rvalue instanceof String) {
                                postParams.add(new BasicNameValuePair(paramName, (String)rvalue));
                            }
                        }
                    } else if (value instanceof String) {
                        postParams.add(new BasicNameValuePair(paramName, (String)value));
                    }
                }
            }
        }

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);
    }

    /**
     * Test for SLING-1677
     */
    @Test
    public void testModifyAceResponseAsJSON() throws IOException, JsonException {
        testUserId = createTestUser();

        testFolderUrl = createTestFolder();

        String postUrl = testFolderUrl + ".modifyAce.json";

        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:write", "denied"));
        postParams.add(new BasicNameValuePair("privilege@jcr:modifyAccessControl", "bogus")); //invalid value should be ignored.

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String json = getAuthenticatedPostContent(creds, postUrl, CONTENT_TYPE_JSON, postParams, HttpServletResponse.SC_OK);

        //make sure the json response can be parsed as a JSON object
        JsonObject jsonObject = parseJson(json);
        assertNotNull(jsonObject);
    }


    /**
     * Test for SLING-3010
     */
    @Test
    public void testMergeAceForUserGrantNestedAggregatePrivilegeAfterDenySuperAggregatePrivilege() throws IOException, JsonException {
        testUserId = createTestUser();

        testFolderUrl = createTestFolder();

        String postUrl = testFolderUrl + ".modifyAce.json";

        //1. setup an initial set of denied privileges for the test user
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:versionManagement", "denied"));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "denied"));
        postParams.add(new BasicNameValuePair("privilege@jcr:modifyAccessControl", "denied"));
        postParams.add(new BasicNameValuePair("privilege@rep:write", "denied"));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        /*String json = */getAuthenticatedPostContent(creds, postUrl, CONTENT_TYPE_JSON, postParams, HttpServletResponse.SC_OK);


        //2. now grant the jcr:write subset from the rep:write aggregate privilege
        postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:versionManagement", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:modifyAccessControl", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:write", "granted")); //sub-aggregate of rep:write

        /*String json = */getAuthenticatedPostContent(creds, postUrl, CONTENT_TYPE_JSON, postParams, HttpServletResponse.SC_OK);

        //3. verify that the acl has the correct values
        //fetch the JSON for the acl to verify the settings.
        String getUrl = testFolderUrl + ".acl.json";

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);

        JsonObject jsonObject = parseJson(json);
        assertEquals(1, jsonObject.size());

        JsonObject aceObject = jsonObject.getJsonObject(testUserId);
        assertNotNull(aceObject);

        assertEquals(testUserId, aceObject.getString("principal"));

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(5, privilegesObject.size());
        //allow privileges
        assertPrivilege(privilegesObject, true, true, PrivilegeConstants.JCR_VERSION_MANAGEMENT);
        assertPrivilege(privilegesObject, true, true, PrivilegeConstants.JCR_READ);
        assertPrivilege(privilegesObject, true, true, PrivilegeConstants.JCR_MODIFY_ACCESS_CONTROL);
        assertPrivilege(privilegesObject, true, true, PrivilegeConstants.JCR_WRITE);
        //deny privileges
        assertPrivilege(privilegesObject, true, false, PrivilegeConstants.JCR_NODE_TYPE_MANAGEMENT);
    }

    /**
     * Test for SLING-3010
     */
    @Test
    public void testMergeAceForUserGrantAggregatePrivilegePartsAfterDenyAggregatePrivilege() throws IOException, JsonException {
        testUserId = createTestUser();

        testFolderUrl = createTestFolder();

        String postUrl = testFolderUrl + ".modifyAce.json";

        //1. setup an initial set of denied privileges for the test user
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:versionManagement", "denied"));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "denied"));
        postParams.add(new BasicNameValuePair("privilege@jcr:modifyAccessControl", "denied"));
        postParams.add(new BasicNameValuePair("privilege@rep:write", "denied"));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        /*String json = */getAuthenticatedPostContent(creds, postUrl, CONTENT_TYPE_JSON, postParams, HttpServletResponse.SC_OK);

        //2. now grant the all the privileges contained in the rep:write privilege
        postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:versionManagement", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:modifyAccessControl", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:nodeTypeManagement", "granted")); //sub-privilege of rep:write
        postParams.add(new BasicNameValuePair("privilege@jcr:write", "granted")); //sub-aggregate of rep:write

        /*String json = */getAuthenticatedPostContent(creds, postUrl, CONTENT_TYPE_JSON, postParams, HttpServletResponse.SC_OK);

        //3. verify that the acl has the correct values
        //fetch the JSON for the acl to verify the settings.
        String getUrl = testFolderUrl + ".acl.json";

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);

        JsonObject jsonObject = parseJson(json);
        assertEquals(1, jsonObject.size());

        JsonObject aceObject = jsonObject.getJsonObject(testUserId);
        assertNotNull(aceObject);

        assertEquals(testUserId, aceObject.getString("principal"));

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(4, privilegesObject.size());
        //allow privileges
        assertPrivilege(privilegesObject, true, true, PrivilegeConstants.JCR_VERSION_MANAGEMENT);
        assertPrivilege(privilegesObject, true, true, PrivilegeConstants.JCR_READ);
        assertPrivilege(privilegesObject, true, true, PrivilegeConstants.JCR_MODIFY_ACCESS_CONTROL);
        assertPrivilege(privilegesObject, true, true, PrivilegeConstants.REP_WRITE);
    }

    /**
     * SLING-8117 - Test to verify adding an ACE with restriction to
     * the ACL
     */
    @Test
    public void testAddAceWithRestriction() throws IOException, JsonException {
        createAceOrderTestFolderWithOneAce();

        testGroupId = createTestGroup();

        Map<String, Object> restrictions = new HashMap<>();
        restrictions.put("rep:glob", "/hello");
        restrictions.put("rep:itemNames", new String[] {"child1", "child2"});

        addOrUpdateAce(testFolderUrl, testGroupId, true, "first", restrictions);

        //fetch the JSON for the acl to verify the settings.
        String getUrl = testFolderUrl + ".acl.json";

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);


        JsonObject jsonObject = parseJson(json);
        assertEquals(2, jsonObject.size());


        JsonObject group = jsonObject.getJsonObject(testGroupId);
        assertNotNull(group);
        assertEquals(testGroupId, group.getString("principal"));
        assertEquals(0, group.getInt("order"));

        JsonObject groupPrivilegesObject = group.getJsonObject("privileges");
        assertNotNull(groupPrivilegesObject);
        assertEquals(2, groupPrivilegesObject.size());

        VerifyAce verifyRestrictions = jsonValue -> {
            assertNotNull(jsonValue);
            assertTrue(jsonValue instanceof JsonObject);
            JsonObject restrictionsObj = (JsonObject)jsonValue;

            JsonValue repGlobValue = restrictionsObj.get("rep:glob");
            assertNotNull(repGlobValue);
            assertTrue(repGlobValue instanceof JsonString);
            assertEquals("/hello", ((JsonString)repGlobValue).getString());

            JsonValue repItemNamesValue = restrictionsObj.get("rep:itemNames");
            assertNotNull(repItemNamesValue);
            assertTrue(repItemNamesValue instanceof JsonArray);
            assertEquals(2, ((JsonArray)repItemNamesValue).size());
        };
        //allow privilege
        assertPrivilege(groupPrivilegesObject, true, true, PrivilegeConstants.JCR_READ, verifyRestrictions);
        //deny privilege
        assertPrivilege(groupPrivilegesObject, true, false, PrivilegeConstants.JCR_WRITE, verifyRestrictions);

        JsonObject user =  jsonObject.getJsonObject(testUserId);
        assertNotNull(user);
        assertEquals(testUserId, user.getString("principal"));
        assertEquals(1, user.getInt("order"));
        JsonObject userPrivilegesObject = user.getJsonObject("privileges");
        assertNotNull(userPrivilegesObject);
        assertEquals(2, userPrivilegesObject.size());
        VerifyAce verifyRestrictions2 = jsonValue -> {
            assertNotNull(jsonValue);
            assertEquals(ValueType.TRUE, jsonValue.getValueType());
        };
        //allow privilege
        assertPrivilege(userPrivilegesObject, true, true, PrivilegeConstants.JCR_READ, verifyRestrictions2);
        //deny privilege
        assertPrivilege(userPrivilegesObject, true, false, PrivilegeConstants.JCR_WRITE, verifyRestrictions2);
    }

    /**
     * SLING-8117 - Test to verify merging an ACE with an existing restriction to
     * the ACL
     */
    @Test
    public void testUpdateAceToMergeNewRestriction() throws IOException, JsonException {
        createAceOrderTestFolderWithOneAce();

        testGroupId = createTestGroup();

        //first create an ACE with the first restriction
        Map<String, Object> restrictions = new HashMap<>();
        restrictions.put("rep:glob", "/hello");

        addOrUpdateAce(testFolderUrl, testGroupId, true, "first", restrictions);

        //fetch the JSON for the acl to verify the settings.
        String getUrl = testFolderUrl + ".acl.json";

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);

        JsonObject jsonObject = parseJson(json);
        assertEquals(2, jsonObject.size());

        JsonObject group = jsonObject.getJsonObject(testGroupId);
        assertNotNull(group);
        assertEquals(testGroupId, group.getString("principal"));
        assertEquals(0, group.getInt("order"));

        //verify restrictions are returned
        JsonObject privilegesObject = group.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(2, privilegesObject.size());
        VerifyAce verifyRestrictions = jsonValue -> {
            assertNotNull(jsonValue);
            assertTrue(jsonValue instanceof JsonObject);
            JsonObject restrictionsObj = (JsonObject)jsonValue;

            JsonValue repGlobValue = restrictionsObj.get("rep:glob");
            assertNotNull(repGlobValue);
            assertTrue(repGlobValue instanceof JsonString);
            assertEquals("/hello", ((JsonString)repGlobValue).getString());
        };
        assertPrivilege(privilegesObject, true, true, PrivilegeConstants.JCR_READ, verifyRestrictions);
        assertPrivilege(privilegesObject, true, false, PrivilegeConstants.JCR_WRITE, verifyRestrictions);



        //second update the ACE with a second restriction
        Map<String, Object> restrictions2 = new HashMap<>();
        restrictions2.put("rep:itemNames", new String[] {"child1", "child2"});

        addOrUpdateAce(testFolderUrl, testGroupId, true, "first", restrictions2);

        String json2 = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json2);

        JsonObject jsonObject2 = parseJson(json2);
        assertEquals(2, jsonObject2.size());

        JsonObject group2 = jsonObject2.getJsonObject(testGroupId);
        assertNotNull(group2);
        assertEquals(testGroupId, group2.getString("principal"));
        assertEquals(0, group2.getInt("order"));

        //verify restrictions are returned
        JsonObject privilegesObject2 = group2.getJsonObject("privileges");
        assertNotNull(privilegesObject2);
        assertEquals(2, privilegesObject2.size());
        VerifyAce verifyRestrictions2 = jsonValue -> {
            assertNotNull(jsonValue);
            assertTrue(jsonValue instanceof JsonObject);
            JsonObject restrictionsObj = (JsonObject)jsonValue;

            JsonValue repGlobValue = restrictionsObj.get("rep:glob");
            assertNotNull(repGlobValue);
            assertTrue(repGlobValue instanceof JsonString);
            assertEquals("/hello", ((JsonString)repGlobValue).getString());

            JsonValue repItemNamesValue = restrictionsObj.get("rep:itemNames");
            assertNotNull(repItemNamesValue);
            assertTrue(repItemNamesValue instanceof JsonArray);
            assertEquals(2, ((JsonArray)repItemNamesValue).size());
        };
        assertPrivilege(privilegesObject2, true, true, PrivilegeConstants.JCR_READ, verifyRestrictions2);
        assertPrivilege(privilegesObject2, true, false, PrivilegeConstants.JCR_WRITE, verifyRestrictions2);
    }

    /**
     * SLING-8117 - Test to verify removing a restriction from an ACE
     */
    @Test
    public void testUpdateAceToRemoveRestriction() throws IOException, JsonException {
        createAceOrderTestFolderWithOneAce();

        testGroupId = createTestGroup();

        //first create an ACE with the restrictions
        Map<String, Object> restrictions = new HashMap<>();
        restrictions.put("rep:glob", "/hello");
        restrictions.put("rep:itemNames", new String[] {"child1", "child2"});

        addOrUpdateAce(testFolderUrl, testGroupId, true, "first", restrictions);

        //fetch the JSON for the acl to verify the settings.
        String getUrl = testFolderUrl + ".acl.json";

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);

        JsonObject jsonObject = parseJson(json);
        assertEquals(2, jsonObject.size());

        JsonObject group = jsonObject.getJsonObject(testGroupId);
        assertNotNull(group);
        assertEquals(testGroupId, group.getString("principal"));
        assertEquals(0, group.getInt("order"));

        //verify restrictions are returned
        JsonObject privilegesObject = group.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(2, privilegesObject.size());
        VerifyAce verifyRestrictions = jsonValue -> {
            assertNotNull(jsonValue);
            assertTrue(jsonValue instanceof JsonObject);
            JsonObject restrictionsObj = (JsonObject)jsonValue;

            JsonValue repGlobValue = restrictionsObj.get("rep:glob");
            assertNotNull(repGlobValue);
            assertTrue(repGlobValue instanceof JsonString);
            assertEquals("/hello", ((JsonString)repGlobValue).getString());

            JsonValue repItemNamesValue = restrictionsObj.get("rep:itemNames");
            assertNotNull(repItemNamesValue);
            assertTrue(repItemNamesValue instanceof JsonArray);
            assertEquals(2, ((JsonArray)repItemNamesValue).size());
        };
        assertPrivilege(privilegesObject, true, true, PrivilegeConstants.JCR_READ, verifyRestrictions);
        assertPrivilege(privilegesObject, true, false, PrivilegeConstants.JCR_WRITE, verifyRestrictions);


        //second remove the restrictions
        Map<String, Object> restrictions2 = new HashMap<>();
        restrictions2.put("rep:glob@Delete", "true");
        restrictions2.put("rep:itemNames@Delete", new String[] {"value does not", "matter"});
        addOrUpdateAce(testFolderUrl, testGroupId, true, "first", restrictions2);

        String json2 = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json2);

        JsonObject jsonObject2 = parseJson(json2);
        assertEquals(2, jsonObject2.size());

        JsonObject group2 = jsonObject2.getJsonObject(testGroupId);
        assertNotNull(group2);
        assertEquals(testGroupId, group2.getString("principal"));
        assertEquals(0, group2.getInt("order"));

        //verify no restrictions are returned
        JsonObject privilegesObject2 = group2.getJsonObject("privileges");
        assertNotNull(privilegesObject2);
        assertEquals(2, privilegesObject2.size());
        VerifyAce verifyRestrictions2 = jsonValue -> {
            assertNotNull(jsonValue);
            assertEquals(ValueType.TRUE, jsonValue.getValueType());
        };
        assertPrivilege(privilegesObject2, true, true, PrivilegeConstants.JCR_READ, verifyRestrictions2);
        assertPrivilege(privilegesObject2, true, false, PrivilegeConstants.JCR_WRITE, verifyRestrictions2);
    }

    /**
     * SLING-8117 - Test to verify removing a restriction from an ACE does not happen
     * if a new value with the same name has also been supplied
     */
    @Test
    public void testUpdateAceToRemoveRestrictionWithConflict() throws IOException, JsonException {
        createAceOrderTestFolderWithOneAce();

        testGroupId = createTestGroup();

        //first create an ACE with the restrictions
        Map<String, Object> restrictions = new HashMap<>();
        restrictions.put("rep:glob", "/hello");

        addOrUpdateAce(testFolderUrl, testGroupId, true, "first", restrictions);

        //fetch the JSON for the acl to verify the settings.
        String getUrl = testFolderUrl + ".acl.json";

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);

        JsonObject jsonObject = parseJson(json);
        assertEquals(2, jsonObject.size());

        JsonObject group = jsonObject.getJsonObject(testGroupId);
        assertNotNull(group);
        assertEquals(testGroupId, group.getString("principal"));
        assertEquals(0, group.getInt("order"));

        //verify restrictions are returned
        JsonObject privilegesObject = group.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(2, privilegesObject.size());
        VerifyAce verifyRestrictions = jsonValue -> {
            assertNotNull(jsonValue);
            assertTrue(jsonValue instanceof JsonObject);
            JsonObject restrictionsObj = (JsonObject)jsonValue;

            JsonValue repGlobValue = restrictionsObj.get("rep:glob");
            assertNotNull(repGlobValue);
            assertTrue(repGlobValue instanceof JsonString);
            assertEquals("/hello", ((JsonString)repGlobValue).getString());
        };
        assertPrivilege(privilegesObject, true, true, PrivilegeConstants.JCR_READ, verifyRestrictions);
        assertPrivilege(privilegesObject, true, false, PrivilegeConstants.JCR_WRITE, verifyRestrictions);


        //second remove the restriction and also supply a new value of the same
        Map<String, Object> restrictions2 = new HashMap<>();
        restrictions2.put("rep:glob@Delete", "true");
        restrictions2.put("rep:glob", "/hello_again");
        addOrUpdateAce(testFolderUrl, testGroupId, true, "first", restrictions2);

        String json2 = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json2);

        JsonObject jsonObject2 = parseJson(json2);
        assertEquals(2, jsonObject2.size());

        JsonObject group2 = jsonObject2.getJsonObject(testGroupId);
        assertNotNull(group2);
        assertEquals(testGroupId, group2.getString("principal"));
        assertEquals(0, group2.getInt("order"));

        //verify restrictions are returned
        JsonObject privilegesObject2 = group2.getJsonObject("privileges");
        assertNotNull(privilegesObject2);
        assertEquals(2, privilegesObject2.size());
        VerifyAce verifyRestrictions2 = jsonValue -> {
            assertNotNull(jsonValue);
            assertTrue(jsonValue instanceof JsonObject);
            JsonObject restrictionsObj = (JsonObject)jsonValue;

            JsonValue repGlobValue = restrictionsObj.get("rep:glob");
            assertNotNull(repGlobValue);
            assertTrue(repGlobValue instanceof JsonString);
            assertEquals("/hello_again", ((JsonString)repGlobValue).getString());
        };
        assertPrivilege(privilegesObject2, true, true, PrivilegeConstants.JCR_READ, verifyRestrictions2);
        assertPrivilege(privilegesObject2, true, false, PrivilegeConstants.JCR_WRITE, verifyRestrictions2);
    }

    /**
     * SLING-8809 - Test to verify submitting an invalid principalId returns a
     * good error message instead of a NullPointerException
     */
    @Test
    public void testModifyAceForInvalidUser() throws IOException, JsonException {
        String invalidUserId = "notRealUser123";

        testFolderUrl = createTestFolder();

        String postUrl = testFolderUrl + ".modifyAce.json";

        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":http-equiv-accept", JSONResponse.RESPONSE_CONTENT_TYPE));
        postParams.add(new BasicNameValuePair("principalId", invalidUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:write", "denied"));
        postParams.add(new BasicNameValuePair("privilege@jcr:modifyAccessControl", "bogus")); //invalid value should be ignored.

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String json = getAuthenticatedPostContent(creds, postUrl, CONTENT_TYPE_JSON, postParams, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        assertNotNull(json);

        JsonObject jsonObject = parseJson(json);
        assertEquals("javax.jcr.RepositoryException: Invalid principalId was submitted.", jsonObject.getString("status.message"));
    }

    /**
     * SLING-8811 - Test to verify that the "changes" list of a modifyAce response
     * returns the list of principals that were changed
     */
    @Test
    public void testModifyAceChangesInResponse() throws IOException, JsonException {
        testUserId = createTestUser();

        testFolderUrl = createTestFolder();

        String postUrl = testFolderUrl + ".modifyAce.json";

        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":http-equiv-accept", JSONResponse.RESPONSE_CONTENT_TYPE));
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "granted"));
        postParams.add(new BasicNameValuePair("privilege@jcr:write", "denied"));
        postParams.add(new BasicNameValuePair("privilege@jcr:modifyAccessControl", "bogus")); //invalid value should be ignored.

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String json = getAuthenticatedPostContent(creds, postUrl, CONTENT_TYPE_JSON, postParams, HttpServletResponse.SC_OK);
        assertNotNull(json);

        JsonObject jsonObject = parseJson(json);
        JsonArray changesArray = jsonObject.getJsonArray("changes");
        assertNotNull(changesArray);
        assertEquals(1, changesArray.size());
        JsonObject change = changesArray.getJsonObject(0);
        assertEquals("modified", change.getString("type"));
        assertEquals(testUserId, change.getString("argument"));
    }

    private void testModifyAceRedirect(String redirectTo, int expectedStatus) throws IOException {
        testUserId = createTestUser();

        testFolderUrl = createTestFolder();

        String postUrl = testFolderUrl + ".modifyAce.html";

        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair("principalId", testUserId));
        postParams.add(new BasicNameValuePair("privilege@jcr:read", "granted"));
        postParams.add(new BasicNameValuePair(":redirect", redirectTo));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, expectedStatus, postParams, null);
    }

    @Test
    public void testModifyAceValidRedirect() throws IOException, JsonException {
        testModifyAceRedirect("/*.html", HttpServletResponse.SC_MOVED_TEMPORARILY);
    }

    @Test
    public void testModifyAceInvalidRedirectWithAuthority() throws IOException, JsonException {
        testModifyAceRedirect("https://sling.apache.org", SC_UNPROCESSABLE_ENTITY);
    }

    @Test
    public void testModifyAceInvalidRedirectWithInvalidURI() throws IOException, JsonException {
        testModifyAceRedirect("https://", SC_UNPROCESSABLE_ENTITY);
    }

}
