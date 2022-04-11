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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.jcr.Node;
import javax.jcr.PropertyType;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.SimpleCredentials;
import javax.jcr.Value;
import javax.jcr.ValueFactory;
import javax.jcr.security.AccessControlException;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;

import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.AccessControlConstants;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.sling.api.resource.ResourceNotFoundException;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.jcr.jackrabbit.accessmanager.GetAcl;
import org.apache.sling.jcr.jackrabbit.accessmanager.LocalPrivilege;
import org.apache.sling.jcr.jackrabbit.accessmanager.ModifyAce;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;

/**
 * Tests for the 'modifyAce' inproc service
 */
@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class ModifyAceServiceIT extends AccessManagerClientTestSupport {

    @Inject
    private ModifyAce modifyAce;

    @Inject
    private GetAcl getAcl;

    @Inject
    protected SlingRepository repository;

    protected Session adminSession;

    private Node testNode;

    @Before
    public void setup() throws RepositoryException {
        adminSession = repository.login(new SimpleCredentials("admin", "admin".toCharArray()));
        assertNotNull("Expected adminSession to not be null", adminSession);
        testNode = adminSession.getRootNode().addNode("testNode");
        adminSession.save();
    }

    @After
    public void teardown() throws RepositoryException {
        adminSession.refresh(false);
        testNode.remove();
        if (adminSession.hasPendingChanges()) {
            adminSession.save();
        }
        adminSession.logout();
    }

    protected JsonObject acl(String path) throws RepositoryException {
        assertNotNull(getAcl);
        JsonObject aclObject = getAcl.getAcl(adminSession, path);
        assertNotNull(aclObject);
        return aclObject;
    }

    protected JsonObject ace(String path, String principalId) throws RepositoryException {
        JsonObject aclObject = acl(path);
        assertNotNull(aclObject);

        JsonObject aceObj = aclObject.getJsonObject(principalId);
        assertNotNull(aceObj);
        assertEquals(principalId, aceObj.getString("principal"));
        return aceObj;
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
    private Value[] vals(int type, String ... value) throws RepositoryException {
        Value[] values = new Value[value.length];
        ValueFactory vf = adminSession.getValueFactory();
        for (int i = 0; i < value.length; i++) {
            values[i] = vf.createValue(value[i], type);
        }
        return values;
    }

    @Test
    public void testModifyAceWithPrivileges() throws RepositoryException {
        assertNotNull(modifyAce);
        modifyAce.modifyAce(adminSession,
                testNode.getPath(),
                "everyone",
                Collections.singletonMap(PrivilegeConstants.JCR_READ, "allow"),
                "first");
        // autosaved, so nothing should be pending
        assertFalse(adminSession.hasPendingChanges());

        JsonObject aceObject = ace(testNode.getPath(), "everyone");
        int order = aceObject.getInt("order");
        assertEquals(0, order);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(1, privilegesObject.size());
        //allow
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_READ);
    }

    @Test
    public void testModifyAceWithPrivilegesUsingPrefixedName() throws RepositoryException {
        assertNotNull(modifyAce);
        modifyAce.modifyAce(adminSession,
                testNode.getPath(),
                "everyone",
                Collections.singletonMap("privilege@" + PrivilegeConstants.JCR_READ, "allow"),
                "first");
        // autosaved, so nothing should be pending
        assertFalse(adminSession.hasPendingChanges());

        JsonObject aceObject = ace(testNode.getPath(), "everyone");
        int order = aceObject.getInt("order");
        assertEquals(0, order);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(1, privilegesObject.size());
        //allow
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_READ);
    }

    @Test
    public void testModifyAceWithPrivilegesAutoSave() throws RepositoryException {
        assertNotNull(modifyAce);
        modifyAce.modifyAce(adminSession,
                testNode.getPath(),
                "everyone",
                Collections.singletonMap(PrivilegeConstants.JCR_READ, "allow"),
                "first",
                false);
        // not autosaved, so should be pending
        assertTrue(adminSession.hasPendingChanges());
        adminSession.save();

        JsonObject aceObject = ace(testNode.getPath(), "everyone");
        int order = aceObject.getInt("order");
        assertEquals(0, order);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(1, privilegesObject.size());
        //allow
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_READ);
    }

    @Test
    public void testModifyAceWithRestrictions() throws RepositoryException {
        assertNotNull(modifyAce);
        modifyAce.modifyAce(adminSession,
                testNode.getPath(),
                "everyone",
                Collections.singletonMap(PrivilegeConstants.JCR_READ, "allow"),
                "first",
                Collections.singletonMap(AccessControlConstants.REP_GLOB, val(PropertyType.STRING, "/hello")),
                Collections.singletonMap(AccessControlConstants.REP_ITEM_NAMES, vals(PropertyType.NAME, "child1", "child2")),
                Collections.emptySet());
        // autosaved, so should be nothing pending
        assertFalse(adminSession.hasPendingChanges());

        JsonObject aceObject = ace(testNode.getPath(), "everyone");
        int order = aceObject.getInt("order");
        assertEquals(0, order);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(1, privilegesObject.size());
        //allow
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_READ);
    }

    @Test
    public void testModifyAceWithRestrictionsAutoSave() throws RepositoryException {
        assertNotNull(modifyAce);
        modifyAce.modifyAce(adminSession,
                testNode.getPath(),
                "everyone",
                Collections.singletonMap(PrivilegeConstants.JCR_READ, "allow"),
                "first",
                Collections.singletonMap(AccessControlConstants.REP_GLOB, val(PropertyType.STRING, "/hello")),
                Collections.singletonMap(AccessControlConstants.REP_ITEM_NAMES, vals(PropertyType.NAME, "child1", "child2")),
                Collections.emptySet(),
                false);
        // not autosaved, so should be changes pending
        assertTrue(adminSession.hasPendingChanges());
        adminSession.save();

        JsonObject aceObject = ace(testNode.getPath(), "everyone");
        int order = aceObject.getInt("order");
        assertEquals(0, order);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(1, privilegesObject.size());
        //allow
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_READ);
    }

    @Test
    public void testModifyAceChangeExistingWithRestrictionsAutoSave() throws RepositoryException {
        assertNotNull(modifyAce);
        Map<String, String> privilegesMap = new HashMap<>();
        privilegesMap.put(PrivilegeConstants.JCR_READ, "allow");
        privilegesMap.put(PrivilegeConstants.JCR_READ_ACCESS_CONTROL, "deny");
        modifyAce.modifyAce(adminSession,
                testNode.getPath(),
                "everyone",
                privilegesMap,
                "first",
                Collections.emptyMap(),
                Collections.emptyMap(),
                Collections.emptySet(),
                false);

        // and now change it again
        modifyAce.modifyAce(adminSession,
                testNode.getPath(),
                "everyone",
                Collections.singletonMap(PrivilegeConstants.JCR_READ, "allow"),
                "first",
                Collections.singletonMap(AccessControlConstants.REP_GLOB, val(PropertyType.STRING, "/hello")),
                Collections.singletonMap(AccessControlConstants.REP_ITEM_NAMES, vals(PropertyType.NAME, "child1", "child2")),
                Collections.emptySet(),
                false);
        // not autosaved, so should be changes pending
        assertTrue(adminSession.hasPendingChanges());
        adminSession.save();

        JsonObject aceObject = ace(testNode.getPath(), "everyone");
        int order = aceObject.getInt("order");
        assertEquals(0, order);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(2, privilegesObject.size());
        //allow
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_READ, jsonValue -> {
            assertNotNull(jsonValue);
            assertTrue(jsonValue instanceof JsonObject);
            JsonObject restrictionsObj = (JsonObject)jsonValue;

            JsonValue repGlobValue = restrictionsObj.get(AccessControlConstants.REP_GLOB);
            assertNotNull(repGlobValue);
            assertTrue(repGlobValue instanceof JsonString);
            assertEquals("/hello", ((JsonString)repGlobValue).getString());
        });
        assertPrivilege(privilegesObject, true, PrivilegeValues.DENY, PrivilegeConstants.JCR_READ_ACCESS_CONTROL);
    }

    @Test
    public void testModifyAceWithInvalidSingleValueRestrictionsName() throws RepositoryException {
        assertNotNull(modifyAce);
        try {
            modifyAce.modifyAce(adminSession,
                    testNode.getPath(),
                    "everyone",
                    Collections.singletonMap(PrivilegeConstants.JCR_READ, "allow"),
                    "first",
                    Collections.singletonMap("invalid_name", val(PropertyType.STRING, "/hello")),
                    Collections.emptyMap(),
                    Collections.emptySet(),
                    false);
            fail("Expected AccessControlException");
        } catch (AccessControlException acex) {
            assertEquals("Invalid restriction name was supplied", acex.getMessage());
        }
    }

    @Test
    public void testModifyAceWithInvalidMultiValueRestrictionsName() throws RepositoryException {
        assertNotNull(modifyAce);
        try {
            modifyAce.modifyAce(adminSession,
                    testNode.getPath(),
                    "everyone",
                    Collections.singletonMap(PrivilegeConstants.JCR_READ, "allow"),
                    "first",
                    Collections.emptyMap(),
                    Collections.singletonMap("invalid_name", vals(PropertyType.NAME, "child1", "child2")),
                    Collections.emptySet(),
                    false);
            fail("Expected AccessControlException");
        } catch (AccessControlException acex) {
            assertEquals("Invalid restriction name was supplied", acex.getMessage());
        }
    }

    @Test
    public void testModifyAceWithLocalPrivileges() throws RepositoryException {
        assertNotNull(modifyAce);
        LocalPrivilege localPrivilege = new LocalPrivilege(adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ));
        localPrivilege.setAllow(true);
        modifyAce.modifyAce(adminSession,
                testNode.getPath(),
                "everyone",
                Collections.singleton(localPrivilege),
                "first",
                false);
        // not autosaved, so should be changes pending
        assertTrue(adminSession.hasPendingChanges());
        adminSession.save();

        JsonObject aceObject = ace(testNode.getPath(), "everyone");
        int order = aceObject.getInt("order");
        assertEquals(0, order);

        JsonObject privilegesObject = aceObject.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        assertEquals(1, privilegesObject.size());
        //allow
        assertPrivilege(privilegesObject, true, PrivilegeValues.ALLOW, PrivilegeConstants.JCR_READ);
    }


    @Test
    public void testModifyAceWithNullSessionArg() throws RepositoryException {
        assertNotNull(modifyAce);
        LocalPrivilege localPrivilege = new LocalPrivilege(adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ));
        localPrivilege.setAllow(true);
        String resourcePath = testNode.getPath();
        try {
            modifyAce.modifyAce(null,
                    resourcePath,
                    "everyone",
                    Collections.singleton(localPrivilege),
                    "first",
                    false);
            fail("Expected RepositoryException");
        } catch (RepositoryException re) {
            assertEquals("JCR Session not found", re.getMessage());
        }
    }

    @Test
    public void testModifyAceWithNullResourcePathArg() throws RepositoryException {
        assertNotNull(modifyAce);
        LocalPrivilege localPrivilege = new LocalPrivilege(adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ));
        localPrivilege.setAllow(true);
        Set<LocalPrivilege> privileges = Collections.singleton(localPrivilege);
        try {
            modifyAce.modifyAce(adminSession,
                    null,
                    "everyone",
                    privileges,
                    "first",
                    false);
            fail("Expected ResourceNotFoundException");
        } catch (ResourceNotFoundException rnfe) {
            //expected
        }
    }

    @Test
    public void testModifyAceWithNotExistingResourcePathArg() throws RepositoryException {
        assertNotNull(modifyAce);
        LocalPrivilege localPrivilege = new LocalPrivilege(adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ));
        localPrivilege.setAllow(true);
        Set<LocalPrivilege> privileges = Collections.singleton(localPrivilege);
        try {
            modifyAce.modifyAce(adminSession,
                    "/not_a_real_path",
                    "everyone",
                    privileges,
                    "first",
                    false);
            fail("Expected ResourceNotFoundException");
        } catch (ResourceNotFoundException rnfe) {
            //expected
        }
    }

    @Test
    public void testModifyAceWithNullPrincipalIdArg() throws RepositoryException {
        assertNotNull(modifyAce);
        LocalPrivilege localPrivilege = new LocalPrivilege(adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ));
        localPrivilege.setAllow(true);
        Set<LocalPrivilege> privileges = Collections.singleton(localPrivilege);
        String resourcePath = testNode.getPath();
        try {
            modifyAce.modifyAce(adminSession,
                    resourcePath,
                    null,
                    privileges,
                    "first",
                    false);
            fail("Expected RepositoryException");
        } catch (RepositoryException re) {
            assertEquals("principalId was not submitted.", re.getMessage());
        }
    }

    @Test
    public void testModifyAceWithNotExistingPrincipalIdArg() throws RepositoryException {
        assertNotNull(modifyAce);
        LocalPrivilege localPrivilege = new LocalPrivilege(adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ));
        localPrivilege.setAllow(true);
        String resourcePath = testNode.getPath();
        try {
            modifyAce.modifyAce(adminSession,
                    resourcePath,
                    "not_a_real_principalid",
                    Collections.singleton(localPrivilege),
                    "first",
                    false);
            fail("Expected RepositoryException");
        } catch (RepositoryException re) {
            assertEquals("Invalid principalId was submitted.", re.getMessage());
        }
    }

}
