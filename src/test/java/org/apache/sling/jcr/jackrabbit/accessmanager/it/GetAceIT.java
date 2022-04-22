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

import java.io.IOException;
import java.util.List;

import javax.json.JsonException;
import javax.json.JsonObject;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.NameValuePair;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;

/**
 * Tests for the 'ace' Sling Get Operation
 */
@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class GetAceIT extends AccessManagerClientTestSupport {

    protected void commonDeclaredAceForUser(String selector) throws IOException {
        testUserId = createTestUser();
        testFolderUrl = createTestFolder(null, "sling-tests",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"child\" : { \"childPropOne\" : true } }");

        //1. create an initial set of privileges
        List<NameValuePair> postParams = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_WRITE, PrivilegeValues.ALLOW)
                .build();
        addOrUpdateAce(testFolderUrl, postParams);

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");

        //fetch the JSON for the ace to verify the settings.
        String getUrl = testFolderUrl + "." + selector + ".json?pid=" + testUserId;

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject aceObject = parseJson(json);

        String principalString = aceObject.getString("principal");
        assertEquals(testUserId, principalString);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(1, privilegesObject.size());
        //allow privilege
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_WRITE);
    }

    /**
     * ACE servlet returns correct information
     */
    @Test
    public void testDeclaredAceForUser() throws IOException, JsonException {
        commonDeclaredAceForUser("ace");
    }

    /**
     * ACE servlet returns correct information
     */
    @Test
    public void testTidyDeclaredAceForUser() throws IOException, JsonException {
        commonDeclaredAceForUser("tidy.ace");
    }

    /**
     * ACE servlet returns 404 when no declared ACE
     */
    @Test
    public void testNoDeclaredAceForUser() throws IOException, JsonException {
        testUserId = createTestUser();
        testFolderUrl = createTestFolder(null, "sling-tests",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"child\" : { \"childPropOne\" : true } }");

        //1. create an initial set of privileges
        List<NameValuePair> postParams = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_WRITE, PrivilegeValues.ALLOW)
                .build();
        addOrUpdateAce(testFolderUrl, postParams);

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");

        //fetch the JSON for the ace to verify the settings.
        String getUrl = testFolderUrl + "/child.ace.json?pid=" + testUserId;
        // no declared access control entry returns a 404
        assertAuthenticatedHttpStatus(creds, getUrl, HttpServletResponse.SC_NOT_FOUND, "Did not expect an ace to be returned");
    }

    /**
     * ACE servlet returns 404 when no read access rights permissions
     */
    @Test
    public void testNoAccessToDeclaredAceForUser() throws IOException, JsonException {
        testUserId = createTestUser();
        testFolderUrl = createTestFolder(null, "sling-tests",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"child\" : { \"childPropOne\" : true } }");

        //1. create an initial set of privileges
        List<NameValuePair> postParams = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_READ_ACCESS_CONTROL, PrivilegeValues.DENY)
                .build();
        addOrUpdateAce(testFolderUrl, postParams);

        Credentials creds = new UsernamePasswordCredentials(testUserId, "testPwd");

        //fetch the JSON for the ace to verify the settings.
        String getUrl = testFolderUrl + "/child.ace.json?pid=" + testUserId;
        // no declared access control entry returns a 404
        assertAuthenticatedHttpStatus(creds, getUrl, HttpServletResponse.SC_NOT_FOUND, "Did not expect an ace to be returned");
    }

}
