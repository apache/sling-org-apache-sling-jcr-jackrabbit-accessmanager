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

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import javax.inject.Inject;
import javax.jcr.Node;
import javax.jcr.PropertyType;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.SimpleCredentials;
import javax.jcr.Value;
import javax.jcr.ValueFactory;
import javax.jcr.security.Privilege;

import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.AccessControlConstants;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.sling.jcr.jackrabbit.accessmanager.ModifyAce;
import org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo;
import org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo.AccessRights;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;

@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class PrivilegesInfoIT extends AccessManagerClientTestSupport {

    private static final String NOT_A_REAL_PATH = "/not_a_real_path";

    @Inject
    private ModifyAce modifyAce;

    protected Session testUserSession;

    private Node testNodeForAdmin;
    private Node testNodeForTestUser;

    @Before
    @Override
    public void before() throws Exception {
        super.before();

        testUserId = createTestUser();
        testNodeForAdmin = adminSession.getRootNode().addNode("testNode");
        setupTestUserAce();
        adminSession.save();

        testUserSession = repository.login(new SimpleCredentials(testUserId, "testPwd".toCharArray()));
        testNodeForTestUser = testUserSession.getNode(testNodeForAdmin.getPath());
    }

    protected void setupTestUserAce() throws RepositoryException {
        assertNotNull(modifyAce);
        Map<String, String> privilegesMap = new HashMap<>();
        privilegesMap.put(PrivilegeConstants.JCR_READ, "allow");
        modifyAce.modifyAce(adminSession,
                testNodeForAdmin.getPath(),
                testUserId,
                privilegesMap,
                "first",
                Collections.emptyMap(),
                Collections.emptyMap(),
                Collections.emptySet(),
                true);
    }

    @After
    @Override
    public void after() throws Exception {
        adminSession.refresh(false);
        testNodeForAdmin.remove();
        if (adminSession.hasPendingChanges()) {
            adminSession.save();
        }
        testUserSession.logout();

        super.after();
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#getSupportedPrivileges(javax.jcr.Node)}.
     */
    @Test
    public void testGetSupportedPrivilegesNode() throws RepositoryException {
        PrivilegesInfo pi = new PrivilegesInfo();
        Privilege[] supportedPrivileges = pi.getSupportedPrivileges(testNodeForAdmin);
        assertNotNull(supportedPrivileges);
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#getSupportedPrivileges(javax.jcr.Session, java.lang.String)}.
     */
    @Test
    public void testGetSupportedPrivilegesSessionString() throws RepositoryException {
        PrivilegesInfo pi = new PrivilegesInfo();
        Privilege[] supportedPrivileges = pi.getSupportedPrivileges(adminSession, testNodeForAdmin.getPath());
        assertNotNull(supportedPrivileges);
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#getDeclaredAccessRights(javax.jcr.Node)}.
     */
    @Test
    public void testGetDeclaredAccessRightsNode() throws RepositoryException {
        setupEveryoneAce();

        PrivilegesInfo pi = new PrivilegesInfo();
        Map<Principal, AccessRights> declaredAccessRights = pi.getDeclaredAccessRights(testNodeForAdmin);
        Optional<Principal> findFirst = declaredAccessRights.keySet().stream()
                .filter(p -> "everyone".equals(p.getName()))
                .findFirst();
        assertTrue(findFirst.isPresent());
        AccessRights rights = declaredAccessRights.get(findFirst.get());
        assertNotNull(rights);
        Privilege jcrReadPrivilege = adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ);
        assertTrue(rights.getGranted().contains(jcrReadPrivilege));
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

    protected void setupEveryoneAce() throws RepositoryException {
        assertNotNull(modifyAce);
        Map<String, String> privilegesMap = new HashMap<>();
        privilegesMap.put(PrivilegeConstants.JCR_READ, "allow");
        privilegesMap.put(PrivilegeConstants.JCR_WRITE, "deny");
        modifyAce.modifyAce(adminSession,
                testNodeForAdmin.getPath(),
                "everyone",
                privilegesMap,
                "first",
                Collections.singletonMap(AccessControlConstants.REP_GLOB, val(PropertyType.STRING, "/hello")),
                Collections.singletonMap(AccessControlConstants.REP_ITEM_NAMES, vals(PropertyType.NAME, "child1", "child2")),
                Collections.emptySet(),
                true);

    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#getDeclaredAccessRights(javax.jcr.Session, java.lang.String)}.
     */
    @Test
    public void testGetDeclaredAccessRightsSessionString() throws RepositoryException {
        setupEveryoneAce();

        PrivilegesInfo pi = new PrivilegesInfo();
        Map<Principal, AccessRights> declaredAccessRights = pi.getDeclaredAccessRights(adminSession, testNodeForAdmin.getPath());
        Optional<Principal> findFirst = declaredAccessRights.keySet().stream()
                .filter(p -> "everyone".equals(p.getName()))
                .findFirst();
        assertTrue(findFirst.isPresent());
        AccessRights rights = declaredAccessRights.get(findFirst.get());
        assertNotNull(rights);
        Privilege jcrReadPrivilege = adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ);
        assertTrue(rights.getGranted().contains(jcrReadPrivilege));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#getDeclaredAccessRightsForPrincipal(javax.jcr.Node, java.lang.String)}.
     */
    @Test
    public void testGetDeclaredAccessRightsForPrincipalNodeString() throws RepositoryException {
        setupEveryoneAce();

        PrivilegesInfo pi = new PrivilegesInfo();
        AccessRights rights = pi.getDeclaredAccessRightsForPrincipal(testNodeForAdmin, "everyone");
        assertNotNull(rights);
        Privilege jcrReadPrivilege = adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ);
        assertTrue(rights.getGranted().contains(jcrReadPrivilege));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#getDeclaredAccessRightsForPrincipal(javax.jcr.Session, java.lang.String, java.lang.String)}.
     */
    @Test
    public void testGetDeclaredAccessRightsForPrincipalSessionStringString() throws RepositoryException {
        setupEveryoneAce();

        PrivilegesInfo pi = new PrivilegesInfo();
        AccessRights rights = pi.getDeclaredAccessRightsForPrincipal(adminSession, testNodeForAdmin.getPath(), "everyone");
        assertNotNull(rights);
        Privilege jcrReadPrivilege = adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ);
        assertTrue(rights.getGranted().contains(jcrReadPrivilege));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#getEffectiveAccessRights(javax.jcr.Node)}.
     */
    @Test
    public void testGetEffectiveAccessRightsNode() throws RepositoryException {
        setupEveryoneAce();

        PrivilegesInfo pi = new PrivilegesInfo();
        Map<Principal, AccessRights> effectiveAccessRights = pi.getEffectiveAccessRights(adminSession, testNodeForAdmin.getPath());
        Optional<Principal> findFirst = effectiveAccessRights.keySet().stream()
                .filter(p -> "everyone".equals(p.getName()))
                .findFirst();
        assertTrue(findFirst.isPresent());
        AccessRights rights = effectiveAccessRights.get(findFirst.get());
        assertNotNull(rights);
        Privilege jcrReadPrivilege = adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ);
        assertTrue(rights.getGranted().contains(jcrReadPrivilege));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#getEffectiveAccessRights(javax.jcr.Session, java.lang.String)}.
     */
    @Test
    public void testGetEffectiveAccessRightsSessionString() throws RepositoryException {
        setupEveryoneAce();

        PrivilegesInfo pi = new PrivilegesInfo();
        Map<Principal, AccessRights> effectiveAccessRights = pi.getEffectiveAccessRights(testNodeForAdmin);
        Optional<Principal> findFirst = effectiveAccessRights.keySet().stream()
                .filter(p -> "everyone".equals(p.getName()))
                .findFirst();
        assertTrue(findFirst.isPresent());
        AccessRights rights = effectiveAccessRights.get(findFirst.get());
        assertNotNull(rights);
        Privilege jcrReadPrivilege = adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ);
        assertTrue(rights.getGranted().contains(jcrReadPrivilege));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#getEffectiveAccessRightsForPrincipal(javax.jcr.Node, java.lang.String)}.
     */
    @Test
    public void testGetEffectiveAccessRightsForPrincipalNodeString() throws RepositoryException {
        setupEveryoneAce();

        PrivilegesInfo pi = new PrivilegesInfo();
        AccessRights rights = pi.getEffectiveAccessRightsForPrincipal(testNodeForAdmin, "everyone");
        assertNotNull(rights);
        Privilege jcrReadPrivilege = adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ);
        assertTrue(rights.getGranted().contains(jcrReadPrivilege));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#getEffectiveAccessRightsForPrincipal(javax.jcr.Session, java.lang.String, java.lang.String)}.
     */
    @Test
    public void testGetEffectiveAccessRightsForPrincipalSessionStringString() throws RepositoryException {
        setupEveryoneAce();

        PrivilegesInfo pi = new PrivilegesInfo();
        AccessRights rights = pi.getEffectiveAccessRightsForPrincipal(adminSession, testNodeForAdmin.getPath(), "everyone");
        assertNotNull(rights);
        Privilege jcrReadPrivilege = adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ);
        assertTrue(rights.getGranted().contains(jcrReadPrivilege));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canAddChildren(javax.jcr.Node)}.
     */
    @Test
    public void testCanAddChildrenNode() {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canAddChildren(testNodeForAdmin));
        assertFalse(pi.canAddChildren(testNodeForTestUser));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canAddChildren(javax.jcr.Session, java.lang.String)}.
     */
    @Test
    public void testCanAddChildrenSessionString() throws RepositoryException {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canAddChildren(adminSession, testNodeForAdmin.getPath()));
        assertFalse(pi.canAddChildren(testUserSession, testNodeForTestUser.getPath()));
        assertFalse(pi.canAddChildren(testUserSession, NOT_A_REAL_PATH));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canDeleteChildren(javax.jcr.Node)}.
     */
    @Test
    public void testCanDeleteChildrenNode() {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canDeleteChildren(testNodeForAdmin));
        assertFalse(pi.canDeleteChildren(testNodeForTestUser));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canDeleteChildren(javax.jcr.Session, java.lang.String)}.
     */
    @Test
    public void testCanDeleteChildrenSessionString() throws RepositoryException {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canDeleteChildren(adminSession, testNodeForAdmin.getPath()));
        assertFalse(pi.canDeleteChildren(testUserSession, testNodeForTestUser.getPath()));
        assertFalse(pi.canDeleteChildren(testUserSession, NOT_A_REAL_PATH));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canDelete(javax.jcr.Node)}.
     */
    @Test
    public void testCanDeleteNode() {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canDelete(testNodeForAdmin));
        assertFalse(pi.canDelete(testNodeForTestUser));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canDelete(javax.jcr.Session, java.lang.String)}.
     */
    @Test
    public void testCanDeleteSessionString() throws RepositoryException {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canDelete(adminSession, testNodeForAdmin.getPath()));
        assertFalse(pi.canDelete(testUserSession, testNodeForTestUser.getPath()));
        assertFalse(pi.canDelete(testUserSession, NOT_A_REAL_PATH));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canModifyProperties(javax.jcr.Node)}.
     */
    @Test
    public void testCanModifyPropertiesNode() {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canModifyProperties(testNodeForAdmin));
        assertFalse(pi.canModifyProperties(testNodeForTestUser));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canModifyProperties(javax.jcr.Session, java.lang.String)}.
     */
    @Test
    public void testCanModifyPropertiesSessionString() throws RepositoryException {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canModifyProperties(adminSession, testNodeForAdmin.getPath()));
        assertFalse(pi.canModifyProperties(testUserSession, testNodeForTestUser.getPath()));
        assertFalse(pi.canModifyProperties(testUserSession, NOT_A_REAL_PATH));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canReadAccessControl(javax.jcr.Node)}.
     */
    @Test
    public void testCanReadAccessControlNode() {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canReadAccessControl(testNodeForAdmin));
        assertFalse(pi.canReadAccessControl(testNodeForTestUser));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canReadAccessControl(javax.jcr.Session, java.lang.String)}.
     */
    @Test
    public void testCanReadAccessControlSessionString() throws RepositoryException {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canReadAccessControl(adminSession, testNodeForAdmin.getPath()));
        assertFalse(pi.canReadAccessControl(testUserSession, testNodeForTestUser.getPath()));
        assertFalse(pi.canReadAccessControl(testUserSession, NOT_A_REAL_PATH));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canModifyAccessControl(javax.jcr.Node)}.
     */
    @Test
    public void testCanModifyAccessControlNode() {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canModifyAccessControl(testNodeForAdmin));
        assertFalse(pi.canModifyAccessControl(testNodeForTestUser));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canModifyAccessControl(javax.jcr.Session, java.lang.String)}.
     */
    @Test
    public void testCanModifyAccessControlSessionString() throws RepositoryException {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canModifyAccessControl(adminSession, testNodeForAdmin.getPath()));
        assertFalse(pi.canModifyAccessControl(testUserSession, testNodeForTestUser.getPath()));
        assertFalse(pi.canModifyAccessControl(testUserSession, NOT_A_REAL_PATH));
    }

    protected AccessRights setupAccessRights() throws RepositoryException {
        AccessRights rights = new AccessRights();
        Privilege jcrReadPrivilege = adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ);
        rights.getGranted().add(jcrReadPrivilege);
        Privilege jcrWritePrivilege = adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_WRITE);
        rights.getDenied().add(jcrWritePrivilege);
        return rights;
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo.AccessRights#getGranted()}.
     */
    @Test
    public void testGetGranted() throws RepositoryException {
        AccessRights rights = setupAccessRights();
        assertTrue(rights.getGranted().contains(adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ)));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo.AccessRights#getDenied()}.
     */
    @Test
    public void testGetDenied() throws RepositoryException {
        AccessRights rights = setupAccessRights();
        assertTrue(rights.getDenied().contains(adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_WRITE)));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo.AccessRights#getPrivilegeSetDisplayName(java.util.Locale)}.
     */
    @Test
    public void testGetPrivilegeSetDisplayName() throws RepositoryException {
        AccessRights rights = new AccessRights();
        //none
        assertEquals("None", rights.getPrivilegeSetDisplayName(Locale.getDefault()));

        //all
        rights.getGranted().add(adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_ALL));
        assertEquals("Full Control", rights.getPrivilegeSetDisplayName(Locale.getDefault()));

        //read-only
        rights.getGranted().clear();
        rights.getGranted().add(adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ));
        assertEquals("Read Only", rights.getPrivilegeSetDisplayName(Locale.getDefault()));

        //read-write
        rights.getGranted().add(adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_WRITE));
        assertEquals("Read/Write", rights.getPrivilegeSetDisplayName(Locale.getDefault()));

        //custom
        rights.getGranted().clear();
        rights.getGranted().add(adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ_ACCESS_CONTROL));
        assertEquals("Custom", rights.getPrivilegeSetDisplayName(Locale.getDefault()));

        //custom
        rights.getGranted().clear();
        rights.getGranted().add(adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ));
        rights.getGranted().add(adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ_ACCESS_CONTROL));
        assertEquals("Custom", rights.getPrivilegeSetDisplayName(Locale.getDefault()));

        //custom
        rights.getGranted().clear();
        rights.getDenied().add(adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_WRITE));
        assertEquals("Custom", rights.getPrivilegeSetDisplayName(Locale.getDefault()));
    }

}
