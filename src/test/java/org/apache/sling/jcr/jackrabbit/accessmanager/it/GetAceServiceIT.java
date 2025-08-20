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

import javax.inject.Inject;
import javax.jcr.Node;
import javax.jcr.PropertyType;
import javax.jcr.RepositoryException;
import javax.jcr.Value;
import javax.jcr.ValueFactory;

import java.util.Collections;

import jakarta.json.JsonObject;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.AccessControlConstants;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.sling.api.resource.ResourceNotFoundException;
import org.apache.sling.jcr.jackrabbit.accessmanager.GetAce;
import org.apache.sling.jcr.jackrabbit.accessmanager.ModifyAce;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

/**
 * Tests for the 'modifyAce' inproc service
 */
@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class GetAceServiceIT extends AccessManagerClientTestSupport {

    @Inject
    private ModifyAce modifyAce;

    @Inject
    private GetAce getAce;

    private Node testNode;

    @Before
    @Override
    public void before() throws Exception {
        super.before();

        testNode = adminSession.getRootNode().addNode("testNode");
        adminSession.save();
    }

    @After
    @Override
    public void after() throws Exception {
        adminSession.refresh(false);
        testNode.remove();
        if (adminSession.hasPendingChanges()) {
            adminSession.save();
        }

        super.after();
    }

    protected JsonObject ace(String path, String principalId) throws RepositoryException {
        assertNotNull(getAce);
        JsonObject aceObject = getAce.getAce(adminSession, path, principalId);
        assertNotNull(aceObject);
        return aceObject;
    }

    protected JsonObject acePrivleges(String path, String principalId) throws RepositoryException {
        JsonObject ace = ace(path, principalId);
        JsonObject privilegesObject = ace.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        return privilegesObject;
    }

    private Value val(int type, String value) throws RepositoryException {
        return adminSession.getValueFactory().createValue(value, type);
    }

    private Value[] vals(int type, String... value) throws RepositoryException {
        Value[] values = new Value[value.length];
        ValueFactory vf = adminSession.getValueFactory();
        for (int i = 0; i < value.length; i++) {
            values[i] = vf.createValue(value[i], type);
        }
        return values;
    }

    @Test
    public void testGetAceWithPrivileges() throws RepositoryException {
        assertNotNull(modifyAce);
        modifyAce.modifyAce(
                adminSession,
                testNode.getPath(),
                "everyone",
                Collections.singletonMap(PrivilegeConstants.JCR_READ, "allow"),
                "first");
        // autosaved, so nothing should be pending
        assertFalse(adminSession.hasPendingChanges());

        JsonObject aceObject = ace(testNode.getPath(), "everyone");

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(1, privilegesObject.size());
        // allow
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_READ);
    }

    @Test
    public void testGetAceWithRestrictions() throws RepositoryException {
        assertNotNull(modifyAce);
        modifyAce.modifyAce(
                adminSession,
                testNode.getPath(),
                "everyone",
                Collections.singletonMap(PrivilegeConstants.JCR_READ, "allow"),
                "first",
                Collections.singletonMap(AccessControlConstants.REP_GLOB, val(PropertyType.STRING, "/hello")),
                Collections.singletonMap(
                        AccessControlConstants.REP_ITEM_NAMES, vals(PropertyType.NAME, "child1", "child2")),
                Collections.emptySet());
        // autosaved, so should be nothing pending
        assertFalse(adminSession.hasPendingChanges());

        JsonObject aceObject = ace(testNode.getPath(), "everyone");

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(1, privilegesObject.size());
        // allow
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_READ);
    }

    @Test
    public void testGetAceWithNullSessionArg() throws RepositoryException {
        assertNotNull(modifyAce);
        String resourcePath = testNode.getPath();
        try {
            getAce.getAce(null, resourcePath, "everyone");
            fail("Expected RepositoryException");
        } catch (RepositoryException re) {
            assertEquals("JCR Session not found", re.getMessage());
        }
    }

    @Test
    public void testGetAceWithNullResourcePathArg() throws RepositoryException {
        assertNotNull(modifyAce);
        try {
            getAce.getAce(adminSession, null, "everyone");
            fail("Expected ResourceNotFoundException");
        } catch (ResourceNotFoundException rnfe) {
            // expected
        }
    }

    @Test
    public void testGetAceWithNotExistingResourcePathArg() throws RepositoryException {
        assertNotNull(modifyAce);
        try {
            getAce.getAce(adminSession, "/not_a_real_path", "everyone");
            fail("Expected ResourceNotFoundException");
        } catch (ResourceNotFoundException rnfe) {
            // expected
        }
    }

    @Test
    public void testGetAceWithNullPrincipalIdArg() throws RepositoryException {
        assertNotNull(modifyAce);
        String resourcePath = testNode.getPath();
        try {
            getAce.getAce(adminSession, resourcePath, null);
            fail("Expected RepositoryException");
        } catch (RepositoryException re) {
            assertEquals("principalId was not submitted.", re.getMessage());
        }
    }

    @Test
    public void testGetAceWithNotExistingPrincipalIdArg() throws RepositoryException {
        assertNotNull(modifyAce);
        String resourcePath = testNode.getPath();
        try {
            getAce.getAce(adminSession, resourcePath, "not_a_real_principalid");
            fail("Expected RepositoryException");
        } catch (RepositoryException re) {
            assertEquals("Invalid principalId was submitted.", re.getMessage());
        }
    }
}
