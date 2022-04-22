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
 * Tests for the 'pace' Sling Get Operation
 */
@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class GetPaceIT extends PrincipalAceTestSupport {

    protected void commonPrivilegeAceForServiceUser(String selector) throws IOException {
        String testServiceUserId = "pacetestuser";
        testFolderUrl = createTestFolder(null, "sling-tests1",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"child\" : { \"childPropOne\" : true } }");

        //1. create an initial set of privileges
        List<NameValuePair> postParams = new AcePostParamsBuilder(testServiceUserId)
                .withPrivilege(PrivilegeConstants.JCR_WRITE, PrivilegeValues.ALLOW)
                .build();
        addOrUpdatePrincipalAce(testFolderUrl, postParams);

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");

        //fetch the JSON for the principal ace to verify the settings.
        String getUrl = testFolderUrl + "." + selector + ".json?pid=" + testServiceUserId;

        String json = getAuthenticatedContent(creds, getUrl, CONTENT_TYPE_JSON, HttpServletResponse.SC_OK);
        assertNotNull(json);
        JsonObject aceObject = parseJson(json);

        String principalString = aceObject.getString("principal");
        assertEquals(testServiceUserId, principalString);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(1, privilegesObject.size());
        //allow privilege
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_WRITE);
    }

    /**
     * Privilege ACE servlet returns correct information
     */
    @Test
    public void testPrivilegeAceForServiceUser() throws IOException, JsonException {
        commonPrivilegeAceForServiceUser("pace");
    }

    /**
     * Privilege ACE servlet returns correct information
     */
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
    public void testNoAccessToPrivilegeAceForUser() throws IOException, JsonException {
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

}
