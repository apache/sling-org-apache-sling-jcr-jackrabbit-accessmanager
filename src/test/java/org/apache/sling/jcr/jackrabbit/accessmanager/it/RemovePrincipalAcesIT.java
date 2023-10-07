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
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.List;

import jakarta.json.JsonArray;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
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
 * Tests for the 'removeAce' Sling POST operation
 */
@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class RemovePrincipalAcesIT extends PrincipalAceTestSupport {

    private ServiceRegistration<PostResponseCreator> serviceReg;

    @Before
    @Override
    public void before() throws Exception {
        Bundle bundle = FrameworkUtil.getBundle(getClass());
        Dictionary<String, Object> props = new Hashtable<>(); // NOSONAR
        serviceReg = bundle.getBundleContext().registerService(PostResponseCreator.class,
                new CustomPostResponseCreatorImpl(), props);

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

    private String createFolderWithPrincipalAces(boolean addSecondUserAce) throws IOException, JsonException {
        testFolderUrl = createTestFolder();
        createPrincipalAces(testFolderUrl, addSecondUserAce);
        return testFolderUrl;
    }
    private String createPrincipalAces(String targetUrl, boolean addSecondUserAce) throws IOException, JsonException {

        // update the ACE
        List<NameValuePair> postParams = new AcePostParamsBuilder("pacetestuser")
                .withPrivilege(PrivilegeConstants.JCR_READ, PrivilegeValues.ALLOW)
                .build();
        addOrUpdatePrincipalAce(targetUrl, postParams);

        if (addSecondUserAce) {
            postParams = new AcePostParamsBuilder("pacetestuser2")
                    .withPrivilege(PrivilegeConstants.JCR_READ, PrivilegeValues.ALLOW)
                    .build();
            addOrUpdatePrincipalAce(targetUrl, postParams);
        }

        //fetch the JSON for the eacl to verify the settings.
        JsonObject aceObject = getPrincipalAce(targetUrl, "pacetestuser");
        assertNotNull(aceObject);

        JsonObject aceObject2 = null;
        if (addSecondUserAce) {
            aceObject2 = getPrincipalAce(targetUrl, "pacetestuser2");
            assertNotNull(aceObject2);
        }

        String principalString = aceObject.getString("principal");
        assertEquals("pacetestuser", principalString);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(1, privilegesObject.size());
        //allow privileges
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_READ);

        if (addSecondUserAce) {
            principalString = aceObject2.getString("principal");
            assertEquals("pacetestuser2", principalString);

            privilegesObject = aceObject2.getJsonObject("privileges");
            assertNotNull(privilegesObject);
            assertEquals(1, privilegesObject.size());
            //allow privileges
            assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_READ);
        }

        return targetUrl;
    }

    //test removing a single ace
    @Test
    public void testRemovePrincipalAce() throws IOException, JsonException {
        String folderUrl = createFolderWithPrincipalAces(false);

        //remove the ace for the testUser principal
        String postUrl = folderUrl + ".deletePAce.html";
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":applyTo", "pacetestuser"));
        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        //fetch the JSON for the ace to verify the settings.
        JsonObject aceObj = getPrincipalAce(folderUrl, "pacetestuser", CONTENT_TYPE_HTML, HttpServletResponse.SC_NOT_FOUND);
        assertNull(aceObj);
    }

    /**
     * Test for SLING-7831
     */
    @Test
    public void testRemovePrincipalAceCustomPostResponse() throws IOException, JsonException {
        String folderUrl = createFolderWithPrincipalAces(false);

        //remove the ace for the testUser principal
        String postUrl = folderUrl + ".deletePAce.html";
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":responseType", "custom"));
        postParams.add(new BasicNameValuePair(":applyTo", "pacetestuser"));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String content = getAuthenticatedPostContent(creds, postUrl, CONTENT_TYPE_HTML, postParams, HttpServletResponse.SC_OK);
        assertEquals("Thanks!", content); //verify that the content matches the custom response
    }

    //test removing multiple aces
    @Test
    public void testRemovePrincipalAces() throws IOException, JsonException {
        String folderUrl = createFolderWithPrincipalAces(true);

        //remove the ace for the testUser principal
        String postUrl = folderUrl + ".deletePAce.html";
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":applyTo", "pacetestuser"));
        postParams.add(new BasicNameValuePair(":applyTo", "pacetestuser2"));
        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        //fetch the JSON for the acl to verify the settings.
        JsonObject aceObj = getPrincipalAce(folderUrl, "pacetestuser", CONTENT_TYPE_HTML, HttpServletResponse.SC_NOT_FOUND);
        assertNull(aceObj);
        JsonObject aceObj2 = getPrincipalAce(folderUrl, "pacetestuser2", CONTENT_TYPE_HTML, HttpServletResponse.SC_NOT_FOUND);
        assertNull(aceObj2);
    }

    /**
     * Test for SLING-1677
     */
    @Test
    public void testRemovePrincipalAcesResponseAsJSON() throws IOException, JsonException {
        String folderUrl = createFolderWithPrincipalAces(true);

        //remove the ace for the testUser principal
        String postUrl = folderUrl + ".deletePAce.json";
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":applyTo", "pacetestuser"));
        postParams.add(new BasicNameValuePair(":applyTo", "pacetestuser2"));
        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String json = getAuthenticatedPostContent(creds, postUrl, CONTENT_TYPE_JSON, postParams, HttpServletResponse.SC_OK);

        //make sure the json response can be parsed as a JSON object
        JsonObject jsonObject = parseJson(json);
        assertNotNull(jsonObject);
    }

    /**
     * SLING-8810 - Test that a attempt to remove an ACE from a
     * node that does not yet have an AccessControlList responds
     * in a consistent way to other scenarios
     */
    @Test
    public void testRemovePrincipalAceWhenAccessControlListDoesNotExist() throws IOException, JsonException {
        testFolderUrl = createTestFolder();

        String postUrl = testFolderUrl + ".deletePAce.json";

        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":http-equiv-accept", JSONResponse.RESPONSE_CONTENT_TYPE));
        postParams.add(new BasicNameValuePair(":applyTo", "pacetestuser"));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String json = getAuthenticatedPostContent(creds, postUrl, CONTENT_TYPE_JSON, postParams, HttpServletResponse.SC_OK);
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
    public void testRemovePrincipalAceForInvalidUser() throws IOException, JsonException {
        String invalidUserId = "notRealUser123";

        String folderUrl = createFolderWithPrincipalAces(false);

        String postUrl = folderUrl + ".deletePAce.json";

        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":http-equiv-accept", JSONResponse.RESPONSE_CONTENT_TYPE));
        postParams.add(new BasicNameValuePair(":applyTo", invalidUserId));

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
    public void testRemovePrincipalAceChangesInResponse() throws IOException, JsonException {
        String folderUrl = createFolderWithPrincipalAces(false);

        String postUrl = folderUrl + ".deletePAce.json";

        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":http-equiv-accept", JSONResponse.RESPONSE_CONTENT_TYPE));
        postParams.add(new BasicNameValuePair(":applyTo", "pacetestuser"));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        String json = getAuthenticatedPostContent(creds, postUrl, CONTENT_TYPE_JSON, postParams, HttpServletResponse.SC_OK);
        assertNotNull(json);

        JsonObject jsonObject = parseJson(json);
        JsonArray changesArray = jsonObject.getJsonArray("changes");
        assertNotNull(changesArray);
        assertEquals(1, changesArray.size());
        JsonObject change = changesArray.getJsonObject(0);
        assertEquals("deleted", change.getString("type"));
        assertEquals("pacetestuser", change.getString("argument"));
    }

    private void testRemovePrincipalAceRedirect(String redirectTo, int expectedStatus) throws IOException {
        String folderUrl = createFolderWithPrincipalAces(false);

        //remove the ace for the testUser principal
        String postUrl = folderUrl + ".deletePAce.html";
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":applyTo", "pacetestuser"));
        postParams.add(new BasicNameValuePair(":redirect", redirectTo));
        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, expectedStatus, postParams, null);
    }

    @Test
    public void testRemovePrincipalAceValidRedirect() throws IOException, JsonException {
        testRemovePrincipalAceRedirect("/*.html", HttpServletResponse.SC_MOVED_TEMPORARILY);
    }

    @Test
    public void testRemovePrincipalAceInvalidRedirectWithAuthority() throws IOException, JsonException {
        testRemovePrincipalAceRedirect("https://sling.apache.org", SC_UNPROCESSABLE_ENTITY);
    }

    @Test
    public void testRemovePrincipalAceInvalidRedirectWithInvalidURI() throws IOException, JsonException {
        testRemovePrincipalAceRedirect("https://", SC_UNPROCESSABLE_ENTITY);
    }

    @Test
    public void testRemovePrincipalAceDoesNothingOnNotEffectivePath() throws IOException, JsonException {
        String folderUrl = createFolderWithPrincipalAces(false);
        String childUrl = createTestFolder(folderUrl.substring(baseServerUri.toString().length()), "child");

        //remove the ace for the testUser principal using the wrong path
        String postUrl = childUrl + ".deletePAce.html";
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":applyTo", "pacetestuser"));
        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        //fetch the JSON for the acl to verify the settings were not removed.
        JsonObject aceObj = getPrincipalAce(folderUrl, "pacetestuser");
        assertNotNull(aceObj);
    }

    protected void commonRemovePrincipalAce(String targetUrl) throws IOException {
        createPrincipalAces(targetUrl, false);

        //remove the ace for the testUser principal
        String postUrl = targetUrl + ".deletePAce.html";
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":applyTo", "pacetestuser"));
        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, null);

        //fetch the JSON for the acl to verify the settings.
        JsonObject aceObj = getPrincipalAce(targetUrl, "pacetestuser", CONTENT_TYPE_HTML, HttpServletResponse.SC_NOT_FOUND);
        assertNull(aceObj);
    }

    @Test
    public void testRemovePrincipalAceOnNullPath() throws IOException, JsonException {
        String targetUrl = String.format("%s/:repository", baseServerUri);
        commonRemovePrincipalAce(targetUrl);
    }

    @Test
    public void testRemovePrincipalAceOnNotExistingPath() throws IOException, JsonException {
        String targetUrl = String.format("%s/not_existing_path", baseServerUri);
        commonRemovePrincipalAce(targetUrl);
    }

}

