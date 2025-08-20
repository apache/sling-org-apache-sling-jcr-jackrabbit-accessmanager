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
import java.util.ArrayList;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.List;

import jakarta.json.JsonArray;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.http.NameValuePair;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.message.BasicNameValuePair;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.sling.servlets.post.JakartaJSONResponse;
import org.apache.sling.servlets.post.JakartaPostResponseCreator;
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Tests for the 'removeAce' Sling POST operation
 */
@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class RemoveAcesIT extends AccessManagerClientTestSupport {

    private ServiceRegistration<JakartaPostResponseCreator> serviceReg;

    @Before
    @Override
    public void before() throws Exception {
        Bundle bundle = FrameworkUtil.getBundle(getClass());
        Dictionary<String, Object> props = new Hashtable<>(); // NOSONAR
        serviceReg = bundle.getBundleContext()
                .registerService(JakartaPostResponseCreator.class, new CustomPostResponseCreatorImpl(), props);

        super.before();
    }

    @After
    @Override
    public void after() throws Exception {
        if (serviceReg != null) {
            serviceReg.unregister();
        }

        super.after();
    }

    private String createFolderWithAces(boolean addGroupAce) throws IOException, JsonException, RepositoryException {
        testUserId = createTestUser();
        testFolderUrl = createTestFolder();

        // update the ACE
        List<NameValuePair> postParams = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_READ, PrivilegeValues.ALLOW)
                .withPrivilege(PrivilegeConstants.JCR_WRITE, PrivilegeValues.DENY)
                .build();
        addOrUpdateAce(testFolderUrl, postParams);

        if (addGroupAce) {
            testGroupId = createTestGroup();

            postParams = new AcePostParamsBuilder(testGroupId)
                    .withPrivilege(PrivilegeConstants.JCR_READ, PrivilegeValues.ALLOW)
                    .build();
            addOrUpdateAce(testFolderUrl, postParams);
        }

        // fetch the JSON for the acl to verify the settings.
        JsonObject jsonObject = getAcl(testFolderUrl);

        if (addGroupAce) {
            assertEquals(2, jsonObject.size());
        } else {
            assertEquals(1, jsonObject.size());
        }

        JsonObject aceObject = jsonObject.getJsonObject(testUserId);
        assertNotNull(aceObject);

        assertEquals(0, aceObject.getInt("order"));

        String principalString = aceObject.getString("principal");
        assertEquals(testUserId, principalString);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(2, privilegesObject.size());
        // allow privileges
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_READ);
        // deny privileges
        assertPrivilege(privilegesObject, true, PrivilegeValues.DENY, PrivilegeConstants.JCR_WRITE);

        if (addGroupAce) {
            aceObject = jsonObject.getJsonObject(testGroupId);
            assertNotNull(aceObject);

            principalString = aceObject.getString("principal");
            assertEquals(testGroupId, principalString);

            assertEquals(1, aceObject.getInt("order"));

            privilegesObject = aceObject.getJsonObject("privileges");
            assertNotNull(privilegesObject);
            assertEquals(1, privilegesObject.size());
            // allow privileges
            assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_READ);
        }

        return testFolderUrl;
    }

    // test removing a single ace
    @Test
    public void testRemoveAce() throws IOException, JsonException, RepositoryException {
        String folderUrl = createFolderWithAces(false);

        // remove the ace for the testUser principal
        String postUrl = folderUrl + ".deleteAce.html";
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":applyTo", testUserId));
        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        // fetch the JSON for the acl to verify the settings.
        String getUrl = folderUrl + ".acl.json";

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);

        JsonObject jsonObject = parseJson(json);
        assertNotNull(jsonObject);
        assertEquals(0, jsonObject.size());
    }

    /**
     * Test for SLING-7831
     */
    @Test
    public void testRemoveAceCustomPostResponse() throws IOException, JsonException, RepositoryException {
        String folderUrl = createFolderWithAces(false);

        // remove the ace for the testUser principal
        String postUrl = folderUrl + ".deleteAce.html";
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":responseType", "custom"));
        postParams.add(new BasicNameValuePair(":applyTo", testUserId));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String content =
                getAuthenticatedPostContent(creds, postUrl, CONTENT_TYPE_HTML, postParams, HttpServletResponse.SC_OK);
        assertEquals("Thanks!", content); // verify that the content matches the custom response
    }

    // test removing multiple aces
    @Test
    public void testRemoveAces() throws IOException, JsonException, RepositoryException {
        String folderUrl = createFolderWithAces(true);

        // remove the ace for the testUser principal
        String postUrl = folderUrl + ".deleteAce.html";
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":applyTo", testUserId));
        postParams.add(new BasicNameValuePair(":applyTo", testGroupId));
        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        // fetch the JSON for the acl to verify the settings.
        String getUrl = folderUrl + ".acl.json";

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);

        JsonObject jsonObject = parseJson(json);
        assertNotNull(jsonObject);
        assertEquals(0, jsonObject.size());
    }

    /**
     * Test for SLING-1677
     */
    @Test
    public void testRemoveAcesResponseAsJSON() throws IOException, JsonException, RepositoryException {
        String folderUrl = createFolderWithAces(true);

        // remove the ace for the testUser principal
        String postUrl = folderUrl + ".deleteAce.json";
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":applyTo", testUserId));
        postParams.add(new BasicNameValuePair(":applyTo", testGroupId));
        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String json =
                getAuthenticatedPostContent(creds, postUrl, CONTENT_TYPE_JSON, postParams, HttpServletResponse.SC_OK);

        // make sure the json response can be parsed as a JSON object
        JsonObject jsonObject = parseJson(json);
        assertNotNull(jsonObject);
    }

    /**
     * SLING-8810 - Test that a attempt to remove an ACE from a
     * node that does not yet have an AccessControlList responds
     * in a consistent way to other scenarios
     */
    @Test
    public void testRemoveAceWhenAccessControlListDoesNotExist()
            throws IOException, JsonException, RepositoryException {
        testUserId = createTestUser();
        testFolderUrl = createTestFolder();

        String postUrl = testFolderUrl + ".deleteAce.json";

        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":http-equiv-accept", JakartaJSONResponse.RESPONSE_CONTENT_TYPE));
        postParams.add(new BasicNameValuePair(":applyTo", testUserId));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String json =
                getAuthenticatedPostContent(creds, postUrl, CONTENT_TYPE_JSON, postParams, HttpServletResponse.SC_OK);
        assertNotNull(json);

        JsonObject jsonObject = parseJson(json);
        JsonArray changesArray = jsonObject.getJsonArray("changes");
        assertNotNull(changesArray);
        assertEquals(0, changesArray.size());
    }

    /**
     * SLING-8812 - Test to verify submitting an invalid principalId returns a
     * good error message instead of a NullPointerException
     */
    @Test
    public void testRemoveAceForInvalidUser() throws IOException, JsonException, RepositoryException {
        String invalidUserId = "notRealUser123";

        String folderUrl = createFolderWithAces(true);

        String postUrl = folderUrl + ".deleteAce.json";

        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":http-equiv-accept", JakartaJSONResponse.RESPONSE_CONTENT_TYPE));
        postParams.add(new BasicNameValuePair(":applyTo", invalidUserId));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String json = getAuthenticatedPostContent(
                creds, postUrl, CONTENT_TYPE_JSON, postParams, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        assertNotNull(json);

        JsonObject jsonObject = parseJson(json);
        assertEquals(
                "javax.jcr.RepositoryException: Invalid principalId was submitted.",
                jsonObject.getString("status.message"));
    }

    /**
     * SLING-8811 - Test to verify that the "changes" list of a modifyAce response
     * returns the list of principals that were changed
     */
    @Test
    public void testRemoveAceChangesInResponse() throws IOException, JsonException, RepositoryException {
        String folderUrl = createFolderWithAces(true);

        String postUrl = folderUrl + ".deleteAce.json";

        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":http-equiv-accept", JakartaJSONResponse.RESPONSE_CONTENT_TYPE));
        postParams.add(new BasicNameValuePair(":applyTo", testUserId));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String json =
                getAuthenticatedPostContent(creds, postUrl, CONTENT_TYPE_JSON, postParams, HttpServletResponse.SC_OK);
        assertNotNull(json);

        JsonObject jsonObject = parseJson(json);
        JsonArray changesArray = jsonObject.getJsonArray("changes");
        assertNotNull(changesArray);
        assertEquals(1, changesArray.size());
        JsonObject change = changesArray.getJsonObject(0);
        assertEquals("deleted", change.getString("type"));
        assertEquals(testUserId, change.getString("argument"));
    }

    private void testRemoveAceRedirect(String redirectTo, int expectedStatus)
            throws IOException, JsonException, RepositoryException {
        String folderUrl = createFolderWithAces(false);

        // remove the ace for the testUser principal
        String postUrl = folderUrl + ".deleteAce.html";
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":applyTo", testUserId));
        postParams.add(new BasicNameValuePair(":redirect", redirectTo));
        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, expectedStatus, postParams, null);
    }

    @Test
    public void testRemoveAceValidRedirect() throws IOException, JsonException, RepositoryException {
        testRemoveAceRedirect("/*.html", HttpServletResponse.SC_MOVED_TEMPORARILY);
    }

    @Test
    public void testRemoveAceInvalidRedirectWithAuthority() throws IOException, JsonException, RepositoryException {
        testRemoveAceRedirect("https://sling.apache.org", SC_UNPROCESSABLE_ENTITY);
    }

    @Test
    public void testRemoveAceInvalidRedirectWithInvalidURI() throws IOException, JsonException, RepositoryException {
        testRemoveAceRedirect("https://", SC_UNPROCESSABLE_ENTITY);
    }
}
