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

import javax.jcr.RepositoryException;

import org.apache.http.NameValuePair;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;

import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Tests for the 'pace' Sling Get Operation
 */
@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class ModifyPrincipalAceIT extends PrincipalAceTestSupport {

    /**
     * Privilege ACE servlet returns correct information
     */
    @SuppressWarnings("java:S2699")
    @Test
    public void testModifyPrivilegeAceForServiceUser() throws IOException, JsonException {
        commonPrivilegeAceForServiceUser("pace");
    }

    /**
     * Privilege ACE servlet returns correct information
     */
    @Test
    public void testModifyPrivilegeAceForServiceUserWithDenyPrivilege() throws IOException, JsonException {
        String testServiceUserId = "pacetestuser";
        testFolderUrl = createTestFolder(null, "sling-tests",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"child\" : { \"childPropOne\" : true } }");

        //1. create an initial set of privileges
        List<NameValuePair> postParams = new AcePostParamsBuilder(testServiceUserId)
                .withPrivilege(PrivilegeConstants.JCR_WRITE, PrivilegeValues.ALLOW)
                .withPrivilege(PrivilegeConstants.JCR_MODIFY_ACCESS_CONTROL, PrivilegeValues.DENY)
                .build();
        String json = addOrUpdatePrincipalAce(testFolderUrl, postParams, CONTENT_TYPE_JSON, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        assertNotNull(json);

        JsonObject jsonObject = parseJson(json);
        assertEquals("java.lang.IllegalArgumentException: Deny privileges are not allowed in a principal ACE", jsonObject.getString("status.message"));
    }

    /**
     * Privilege ACE servlet returns error for non-service user
     */
    @Test
    public void testModifyPrivilegeAceForNonServiceUser() throws IOException, JsonException, RepositoryException {
        testUserId = createTestUser();
        testFolderUrl = createTestFolder(null, "sling-tests",
                "{ \"jcr:primaryType\": \"nt:unstructured\", \"child\" : { \"childPropOne\" : true } }");

        //1. create an initial set of privileges
        List<NameValuePair> postParams = new AcePostParamsBuilder(testUserId)
                .withPrivilege(PrivilegeConstants.JCR_WRITE, PrivilegeValues.ALLOW)
                .build();
        String json = addOrUpdatePrincipalAce(testFolderUrl, postParams, CONTENT_TYPE_JSON, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        assertNotNull(json);

        JsonObject jsonObject = parseJson(json);
        assertEquals("java.lang.IllegalStateException: No access control list is available so unable to process", jsonObject.getString("status.message"));
    }

    /**
     * Privilege ACE servlet returns correct information
     */
    @SuppressWarnings("java:S2699")
    @Test
    public void testModifyPrivilegeAceForServiceUserOnNullPath() throws IOException, JsonException {
        String targetUrl = String.format("%s/:repository", baseServerUri);
        commonPrivilegeAceForServiceUser(targetUrl, "pace");
    }

    /**
     * Privilege ACE servlet returns correct information
     */
    @SuppressWarnings("java:S2699")
    @Test
    public void testModifyPrivilegeAceForServiceUserOnNotExistingPath() throws IOException, JsonException {
        String targetUrl = String.format("%s/not_existing_path", baseServerUri);
        commonPrivilegeAceForServiceUser(targetUrl, "pace");
    }

}
