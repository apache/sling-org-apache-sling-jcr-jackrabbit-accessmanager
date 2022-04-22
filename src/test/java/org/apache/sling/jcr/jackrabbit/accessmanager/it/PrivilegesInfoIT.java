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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.Principal;
import java.util.Collections;
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
import org.apache.sling.jcr.api.SlingRepository;
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

    @Inject
    private ModifyAce modifyAce;

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

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#getSupportedPrivileges(javax.jcr.Node)}.
     */
    @Test
    public void testGetSupportedPrivilegesNode() throws RepositoryException {
        PrivilegesInfo pi = new PrivilegesInfo();
        Privilege[] supportedPrivileges = pi.getSupportedPrivileges(testNode);
        assertNotNull(supportedPrivileges);
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#getSupportedPrivileges(javax.jcr.Session, java.lang.String)}.
     */
    @Test
    public void testGetSupportedPrivilegesSessionString() throws RepositoryException {
        PrivilegesInfo pi = new PrivilegesInfo();
        Privilege[] supportedPrivileges = pi.getSupportedPrivileges(adminSession, testNode.getPath());
        assertNotNull(supportedPrivileges);
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#getDeclaredAccessRights(javax.jcr.Node)}.
     */
    @Test
    public void testGetDeclaredAccessRightsNode() throws RepositoryException {
        setupEveryoneAce();

        PrivilegesInfo pi = new PrivilegesInfo();
        Map<Principal, AccessRights> declaredAccessRights = pi.getDeclaredAccessRights(testNode);
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
        modifyAce.modifyAce(adminSession,
                testNode.getPath(),
                "everyone",
                Collections.singletonMap(PrivilegeConstants.JCR_READ, "allow"),
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
        Map<Principal, AccessRights> declaredAccessRights = pi.getDeclaredAccessRights(adminSession, testNode.getPath());
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
        AccessRights rights = pi.getDeclaredAccessRightsForPrincipal(testNode, "everyone");
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
        AccessRights rights = pi.getDeclaredAccessRightsForPrincipal(adminSession, testNode.getPath(), "everyone");
        assertNotNull(rights);
        Privilege jcrReadPrivilege = adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ);
        assertTrue(rights.getGranted().contains(jcrReadPrivilege));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#getDeclaredRestrictionsForPrincipal(javax.jcr.Node, java.lang.String)}.
     * @deprecated api deprecated, test left for regression testing
     */
    @Deprecated
    @Test
    public void testGetDeclaredRestrictionsForPrincipalNodeString() throws RepositoryException {
        setupEveryoneAce();

        PrivilegesInfo pi = new PrivilegesInfo();
        Map<String, Object> restrictions = pi.getDeclaredRestrictionsForPrincipal(testNode, "everyone");
        assertNotNull(restrictions);
        assertEquals(val(PropertyType.STRING, "/hello"), restrictions.get(AccessControlConstants.REP_GLOB));
        assertArrayEquals(vals(PropertyType.NAME, "child1", "child2"), (Value[])restrictions.get(AccessControlConstants.REP_ITEM_NAMES));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#getDeclaredRestrictionsForPrincipal(javax.jcr.Session, java.lang.String, java.lang.String)}.
     * @deprecated api deprecated, test left for regression testing
     */
    @Deprecated
    @Test
    public void testGetDeclaredRestrictionsForPrincipalSessionStringString() throws RepositoryException {
        setupEveryoneAce();

        PrivilegesInfo pi = new PrivilegesInfo();
        Map<String, Object> restrictions = pi.getDeclaredRestrictionsForPrincipal(adminSession, testNode.getPath(), "everyone");
        assertNotNull(restrictions);
        assertEquals(val(PropertyType.STRING, "/hello"), restrictions.get(AccessControlConstants.REP_GLOB));
        assertArrayEquals(vals(PropertyType.NAME, "child1", "child2"), (Value[])restrictions.get(AccessControlConstants.REP_ITEM_NAMES));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#getEffectiveAccessRights(javax.jcr.Node)}.
     */
    @Test
    public void testGetEffectiveAccessRightsNode() throws RepositoryException {
        setupEveryoneAce();

        PrivilegesInfo pi = new PrivilegesInfo();
        Map<Principal, AccessRights> effectiveAccessRights = pi.getEffectiveAccessRights(adminSession, testNode.getPath());
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
        Map<Principal, AccessRights> effectiveAccessRights = pi.getEffectiveAccessRights(testNode);
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
        AccessRights rights = pi.getEffectiveAccessRightsForPrincipal(testNode, "everyone");
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
        AccessRights rights = pi.getEffectiveAccessRightsForPrincipal(adminSession, testNode.getPath(), "everyone");
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
        assertTrue(pi.canAddChildren(testNode));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canAddChildren(javax.jcr.Session, java.lang.String)}.
     */
    @Test
    public void testCanAddChildrenSessionString() throws RepositoryException {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canAddChildren(adminSession, testNode.getPath()));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canDeleteChildren(javax.jcr.Node)}.
     */
    @Test
    public void testCanDeleteChildrenNode() {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canDeleteChildren(testNode));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canDeleteChildren(javax.jcr.Session, java.lang.String)}.
     */
    @Test
    public void testCanDeleteChildrenSessionString() throws RepositoryException {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canDeleteChildren(adminSession, testNode.getPath()));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canDelete(javax.jcr.Node)}.
     */
    @Test
    public void testCanDeleteNode() {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canDelete(testNode));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canDelete(javax.jcr.Session, java.lang.String)}.
     */
    @Test
    public void testCanDeleteSessionString() throws RepositoryException {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canDelete(adminSession, testNode.getPath()));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canModifyProperties(javax.jcr.Node)}.
     */
    @Test
    public void testCanModifyPropertiesNode() {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canModifyProperties(testNode));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canModifyProperties(javax.jcr.Session, java.lang.String)}.
     */
    @Test
    public void testCanModifyPropertiesSessionString() throws RepositoryException {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canModifyProperties(adminSession, testNode.getPath()));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canReadAccessControl(javax.jcr.Node)}.
     */
    @Test
    public void testCanReadAccessControlNode() {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canReadAccessControl(testNode));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canReadAccessControl(javax.jcr.Session, java.lang.String)}.
     */
    @Test
    public void testCanReadAccessControlSessionString() throws RepositoryException {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canReadAccessControl(adminSession, testNode.getPath()));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canModifyAccessControl(javax.jcr.Node)}.
     */
    @Test
    public void testCanModifyAccessControlNode() {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canModifyAccessControl(testNode));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo#canModifyAccessControl(javax.jcr.Session, java.lang.String)}.
     */
    @Test
    public void testCanModifyAccessControlSessionString() throws RepositoryException {
        PrivilegesInfo pi = new PrivilegesInfo();
        assertTrue(pi.canModifyAccessControl(adminSession, testNode.getPath()));
    }

}
