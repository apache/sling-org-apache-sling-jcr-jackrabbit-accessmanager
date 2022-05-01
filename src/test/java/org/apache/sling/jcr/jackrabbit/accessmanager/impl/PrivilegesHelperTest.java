/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to You under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.sling.jcr.jackrabbit.accessmanager.impl;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.Value;
import javax.jcr.ValueFactory;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.Privilege;

import org.apache.jackrabbit.oak.security.authorization.restriction.RestrictionProviderImpl;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.AccessControlConstants;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionDefinition;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.jackrabbit.value.ValueFactoryImpl;
import org.apache.sling.jcr.base.util.AccessControlUtil;
import org.apache.sling.jcr.jackrabbit.accessmanager.LocalPrivilege;
import org.apache.sling.jcr.jackrabbit.accessmanager.LocalRestriction;
import org.apache.sling.testing.mock.sling.ResourceResolverType;
import org.apache.sling.testing.mock.sling.junit.SlingContext;
import org.jetbrains.annotations.Nullable;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

public class PrivilegesHelperTest {

    @Rule
    public final SlingContext context = new SlingContext(ResourceResolverType.JCR_OAK);

    private AccessControlManager acm;

    private Map<Privilege, Integer> privilegeLongestDepthMap;
    private Map<String, RestrictionDefinition> srMap;

    @Before
    public void buildPrivilegesMap() throws RepositoryException {
        context.registerService(new RestrictionProviderImpl());
        Session session = context.resourceResolver().adaptTo(Session.class);
        acm = AccessControlUtil.getAccessControlManager(session);
        Privilege jcrAll = acm.privilegeFromName(PrivilegeConstants.JCR_ALL);
        privilegeLongestDepthMap = PrivilegesHelper.buildPrivilegeLongestDepthMap(jcrAll);
    }

    private Privilege priv(String privilegeName) throws RepositoryException {
        return acm.privilegeFromName(privilegeName);
    }

    private RestrictionDefinition rd(String restrictionName) {
        if (srMap == null) {
            //make a temp map for quick lookup below
            RestrictionProvider restrictionProvider = context.getService(RestrictionProvider.class);
            Set<RestrictionDefinition> supportedRestrictions = restrictionProvider.getSupportedRestrictions("/");
            srMap = new HashMap<>();
            for (RestrictionDefinition restrictionDefinition : supportedRestrictions) {
                srMap.put(restrictionDefinition.getName(), restrictionDefinition);
            }
        }
        return srMap.get(restrictionName);
    }

    private Value val(String value) {
        return ValueFactoryImpl.getInstance().createValue(value);
    }
    private Value[] vals(String ... value) {
        Value[] values = new Value[value.length];
        ValueFactory vf = ValueFactoryImpl.getInstance();
        for (int i = 0; i < value.length; i++) {
            values[i] = vf.createValue(value[i]);
        }
        return values;
    }

    @Test
    public void testConsolidateAggregatesPartial() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        // allow jcr:all
        PrivilegesHelper.allow(merged, Collections.emptySet(),
                Collections.singleton(priv(PrivilegeConstants.JCR_ALL)));

        // deny jcr:read
        PrivilegesHelper.deny(merged, Collections.emptySet(),
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));
        PrivilegesHelper.allow(merged, Collections.emptySet(),
                Collections.singleton(priv(PrivilegeConstants.REP_READ_PROPERTIES)));

        @Nullable
        Session jcrSession = context.resourceResolver().adaptTo(Session.class);
        PrivilegesHelper.consolidateAggregates(jcrSession, "/", merged, privilegeLongestDepthMap);

        Set<Privilege> allowSet = merged.values().stream()
                .filter(lp -> lp.isAllow())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());
        Set<Privilege> denySet = merged.values().stream()
                .filter(lp -> lp.isDeny())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());

        assertEquals(14, allowSet.size());
        assertThat(allowSet, not(hasItems(
                priv(PrivilegeConstants.JCR_ALL),
                priv(PrivilegeConstants.JCR_READ))));
        assertThat(allowSet, hasItems(
                priv(PrivilegeConstants.JCR_LOCK_MANAGEMENT),
                priv(PrivilegeConstants.JCR_LIFECYCLE_MANAGEMENT),
                priv(PrivilegeConstants.JCR_MODIFY_ACCESS_CONTROL),
                priv(PrivilegeConstants.JCR_NAMESPACE_MANAGEMENT),
                priv(PrivilegeConstants.JCR_NODE_TYPE_DEFINITION_MANAGEMENT),
                priv(PrivilegeConstants.JCR_READ_ACCESS_CONTROL),
                priv(PrivilegeConstants.JCR_RETENTION_MANAGEMENT),
                priv(PrivilegeConstants.JCR_VERSION_MANAGEMENT),
                priv(PrivilegeConstants.JCR_WORKSPACE_MANAGEMENT),
                priv(PrivilegeConstants.REP_INDEX_DEFINITION_MANAGEMENT),
                priv(PrivilegeConstants.REP_PRIVILEGE_MANAGEMENT),
                priv(PrivilegeConstants.REP_USER_MANAGEMENT),
                priv(PrivilegeConstants.REP_WRITE),
                priv(PrivilegeConstants.REP_READ_PROPERTIES)));

        assertEquals(1, denySet.size());
        assertThat(denySet, hasItems(priv(PrivilegeConstants.REP_READ_NODES)));
    }

    @Test
    public void testConsolidateAggregatesFull() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        // allow jcr:write
        PrivilegesHelper.allow(merged, Collections.emptySet(),
                Collections.singleton(priv(PrivilegeConstants.JCR_WRITE)));

        // deny jcr:read
        PrivilegesHelper.deny(merged, Collections.emptySet(),
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));

        @Nullable
        Session jcrSession = context.resourceResolver().adaptTo(Session.class);
        PrivilegesHelper.consolidateAggregates(jcrSession, "/", merged, privilegeLongestDepthMap);

        Set<Privilege> allowSet = merged.values().stream()
                .filter(lp -> lp.isAllow())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());
        Set<Privilege> denySet = merged.values().stream()
                .filter(lp -> lp.isDeny())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());

        assertEquals(1, allowSet.size());
        assertThat(allowSet, hasItems(
                priv(PrivilegeConstants.JCR_WRITE)));

        assertEquals(1, denySet.size());
        assertThat(denySet, hasItems(priv(PrivilegeConstants.JCR_READ)));
    }

    @Test
    public void testBuildPrivilegeLongestDepthMap() throws RepositoryException {
        assertEquals(Integer.valueOf(1), privilegeLongestDepthMap.get(priv(PrivilegeConstants.JCR_ALL)));
        assertEquals(Integer.valueOf(2), privilegeLongestDepthMap.get(priv(PrivilegeConstants.JCR_READ)));
        assertEquals(Integer.valueOf(3), privilegeLongestDepthMap.get(priv(PrivilegeConstants.JCR_WRITE)));
        assertEquals(Integer.valueOf(5), privilegeLongestDepthMap.get(priv(PrivilegeConstants.REP_ADD_PROPERTIES)));
    }

    @Test
    public void testAllowLocalPriv() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        LocalPrivilege allowLocalPriv = PrivilegesHelper.localAllowPriv(merged,
                priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES), true, Collections.emptySet());
        assertNotNull(allowLocalPriv);
        assertEquals(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES), allowLocalPriv.getPrivilege());
        assertTrue(allowLocalPriv.isAllow());
        assertTrue(allowLocalPriv.getAllowRestrictions().isEmpty());
        assertFalse(allowLocalPriv.isDeny());
    }

    @Test
    public void testAllowLocalPrivWithSameRestrictionsAsDeny() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        PrivilegesHelper.localDenyPriv(merged,
                priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES), true, Collections.emptySet());

        LocalPrivilege allowLocalPriv = PrivilegesHelper.localAllowPriv(merged,
                priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES), true, Collections.emptySet());
        assertNotNull(allowLocalPriv);
        assertEquals(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES), allowLocalPriv.getPrivilege());
        assertTrue(allowLocalPriv.isAllow());
        assertTrue(allowLocalPriv.getAllowRestrictions().isEmpty());
        assertFalse(allowLocalPriv.isDeny());
    }

    @Test
    public void testAllowLocalPrivWithDifferentRestrictionsAsDeny() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        PrivilegesHelper.localDenyPriv(merged,
                priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES), true, Collections.emptySet());

        LocalPrivilege allowLocalPriv = PrivilegesHelper.localAllowPriv(merged,
                priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES), true, 
                Collections.singleton(new LocalRestriction(rd(AccessControlConstants.REP_GLOB), val("/hello"))));
        assertNotNull(allowLocalPriv);
        assertEquals(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES), allowLocalPriv.getPrivilege());
        assertTrue(allowLocalPriv.isAllow());
        assertEquals(Collections.singleton(new LocalRestriction(rd(AccessControlConstants.REP_GLOB), val("/hello"))),
                allowLocalPriv.getAllowRestrictions());
        assertTrue(allowLocalPriv.isDeny());
        assertTrue(allowLocalPriv.getDenyRestrictions().isEmpty());
    }

    @Test
    public void testDenyLocalPriv() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        LocalPrivilege denyLocalPriv = PrivilegesHelper.localDenyPriv(merged,
                priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES), true, Collections.emptySet());
        assertNotNull(denyLocalPriv);
        assertEquals(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES), denyLocalPriv.getPrivilege());
        assertFalse(denyLocalPriv.isAllow());
        assertTrue(denyLocalPriv.isDeny());
        assertTrue(denyLocalPriv.getAllowRestrictions().isEmpty());
    }

    @Test
    public void testAllow() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        // allow jcr:modifyProperties
        PrivilegesHelper.allow(merged, Collections.emptySet(),
                Collections.singleton(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES)));

        Set<Privilege> allowSet = merged.values().stream()
                .filter(lp -> lp.isAllow())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());

        assertThat(allowSet.size(), equalTo(3));
        assertThat(allowSet, not(hasItems(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES))));
        assertThat(allowSet, hasItems(
                priv(PrivilegeConstants.REP_ADD_PROPERTIES),
                priv(PrivilegeConstants.REP_ALTER_PROPERTIES),
                priv(PrivilegeConstants.REP_REMOVE_PROPERTIES)));
    }

    @Test
    public void testUnallow() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        // allow jcr:modifyProperties
        PrivilegesHelper.allow(merged, Collections.emptySet(),
                Collections.singleton(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES)));

        Set<Privilege> allowSet = merged.values().stream()
                .filter(lp -> lp.isAllow())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());

        assertThat(allowSet.size(), equalTo(3));
        assertThat(allowSet, not(hasItems(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES))));
        assertThat(allowSet, hasItems(
                priv(PrivilegeConstants.REP_ADD_PROPERTIES),
                priv(PrivilegeConstants.REP_ALTER_PROPERTIES),
                priv(PrivilegeConstants.REP_REMOVE_PROPERTIES)));

        // unallow jcr:modifyProperties
        PrivilegesHelper.unallow(merged,
                Collections.singleton(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES)));

        Set<Privilege> allowSet2 = merged.values().stream()
                .filter(lp -> lp.isAllow())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());

        assertEquals(0, allowSet2.size());
    }

    @Test
    public void testDeny() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        // deny jcr:modifyProperties
        PrivilegesHelper.deny(merged, Collections.emptySet(),
                Collections.singleton(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES)));

        Set<Privilege> denySet = merged.values().stream()
                .filter(lp -> lp.isDeny())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());

        assertThat(denySet.size(), equalTo(3));
        assertThat(denySet, not(hasItems(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES))));
        assertThat(denySet, hasItems(
                priv(PrivilegeConstants.REP_ADD_PROPERTIES),
                priv(PrivilegeConstants.REP_ALTER_PROPERTIES),
                priv(PrivilegeConstants.REP_REMOVE_PROPERTIES)));
    }

    @Test
    public void testUndeny() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        // deny jcr:modifyProperties
        PrivilegesHelper.deny(merged, Collections.emptySet(),
                Collections.singleton(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES)));

        Set<Privilege> denySet = merged.values().stream()
                .filter(lp -> lp.isDeny())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());

        assertThat(denySet.size(), equalTo(3));
        assertThat(denySet, not(hasItems(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES))));
        assertThat(denySet, hasItems(
                priv(PrivilegeConstants.REP_ADD_PROPERTIES),
                priv(PrivilegeConstants.REP_ALTER_PROPERTIES),
                priv(PrivilegeConstants.REP_REMOVE_PROPERTIES)));

        // undeny jcr:modifyProperties
        PrivilegesHelper.undeny(merged,
                Collections.singleton(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES)));

        Set<Privilege> denySet2 = merged.values().stream()
                .filter(lp -> lp.isDeny())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());

        assertEquals(0, denySet2.size());
    }

    @Test
    public void testNone() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        // allow jcr:read
        PrivilegesHelper.allow(merged, Collections.emptySet(),
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));

        // deny jcr:modifyProperties
        PrivilegesHelper.deny(merged, Collections.emptySet(),
                Collections.singleton(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES)));

        Set<Privilege> allowSet = merged.values().stream()
                .filter(lp -> lp.isAllow())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());
        Set<Privilege> denySet = merged.values().stream()
                .filter(lp -> lp.isDeny())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());

        assertEquals(2, allowSet.size());
        assertEquals(3, denySet.size());

        // undeny jcr:modifyProperties
        PrivilegesHelper.none(merged, Arrays.asList(priv(PrivilegeConstants.JCR_READ),
                priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES)));

        Set<Privilege> allowSet2 = merged.values().stream()
                .filter(lp -> lp.isAllow())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());
        Set<Privilege> denySet2 = merged.values().stream()
                .filter(lp -> lp.isDeny())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());

        assertEquals(0, allowSet2.size());
        assertEquals(0, denySet2.size());
    }

    @Test
    public void testAllowRestriction() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        // allow jcr:read with restriction
        PrivilegesHelper.allowRestriction(merged,
                new LocalRestriction(rd(AccessControlConstants.REP_GLOB), val("/hello")),
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));

        // allow jcr:modifyProperties with restriction
        PrivilegesHelper.allowRestriction(merged,
                new LocalRestriction(rd(AccessControlConstants.REP_ITEM_NAMES), vals("item1", "item2")),
                Collections.singleton(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES)));

        Set<Privilege> allowSet = merged.values().stream()
                .filter(lp -> lp.isAllow())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());

        assertEquals(5, allowSet.size());

        Set<LocalRestriction> readAllowRestrictions =
                merged.get(priv(PrivilegeConstants.REP_READ_PROPERTIES)).getAllowRestrictions();
        assertEquals(1, readAllowRestrictions.size());
        assertEquals(new LocalRestriction(rd(AccessControlConstants.REP_GLOB), val("/hello")),
                readAllowRestrictions.iterator().next());

        Set<LocalRestriction> modifyAllowRestrictions =
                merged.get(priv(PrivilegeConstants.REP_ADD_PROPERTIES)).getAllowRestrictions();
        assertEquals(1, modifyAllowRestrictions.size());
        assertEquals(new LocalRestriction(rd(AccessControlConstants.REP_ITEM_NAMES), vals("item1", "item2")),
                modifyAllowRestrictions.iterator().next());
    }

    @Test
    public void testUnallowRestriction() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        // allow jcr:read with restriction
        PrivilegesHelper.allowRestriction(merged, 
                new LocalRestriction(rd(AccessControlConstants.REP_GLOB), val("/hello")),
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));
        // allow jcr:modifyProperties with restriction
        PrivilegesHelper.allowRestriction(merged, 
                new LocalRestriction(rd(AccessControlConstants.REP_ITEM_NAMES), vals("item1", "item2")),
                Collections.singleton(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES)));

        // unallow jcr:read with restriction
        PrivilegesHelper.unallowRestriction(merged, AccessControlConstants.REP_GLOB,
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));
        // unallow jcr:modifyProperties with restriction
        PrivilegesHelper.unallowRestriction(merged, AccessControlConstants.REP_ITEM_NAMES,
                Collections.singleton(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES)));

        Set<Privilege> allowSet = merged.values().stream()
                .filter(lp -> lp.isAllow())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());

        assertEquals(5, allowSet.size());

        Set<LocalRestriction> readAllowRestrictions = 
                merged.get(priv(PrivilegeConstants.REP_READ_PROPERTIES)).getAllowRestrictions();
        assertTrue(readAllowRestrictions.isEmpty());

        Set<LocalRestriction> modifyAllowRestrictions = 
                merged.get(priv(PrivilegeConstants.REP_ADD_PROPERTIES)).getAllowRestrictions();
        assertTrue(modifyAllowRestrictions.isEmpty());
    }

    @Test
    public void testUnallowRestrictionNotExisting() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        // allow jcr:read with restriction
        PrivilegesHelper.allowRestriction(merged, 
                new LocalRestriction(rd(AccessControlConstants.REP_GLOB), val("/hello")),
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));

        // unallow jcr:read with restriction that has not been added
        PrivilegesHelper.unallowRestriction(merged, AccessControlConstants.REP_NT_NAMES,
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));

        Set<Privilege> allowSet = merged.values().stream()
                .filter(lp -> lp.isAllow())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());

        assertEquals(2, allowSet.size());

        Set<LocalRestriction> readAllowRestrictions =
                merged.get(priv(PrivilegeConstants.REP_READ_PROPERTIES)).getAllowRestrictions();
        assertEquals(1, readAllowRestrictions.size());
        assertEquals(new LocalRestriction(rd(AccessControlConstants.REP_GLOB), val("/hello")),
                readAllowRestrictions.iterator().next());
    }

    @Test
    public void testUnallowRestrictions() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        // allow jcr:read with restriction
        PrivilegesHelper.allowRestriction(merged,
                new LocalRestriction(rd(AccessControlConstants.REP_GLOB), val("/hello")),
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));
        // allow jcr:read with restriction
        PrivilegesHelper.allowRestriction(merged,
                new LocalRestriction(rd(AccessControlConstants.REP_ITEM_NAMES), vals("item1", "item2")),
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));

        // unallow jcr:read with restriction
        PrivilegesHelper.unallowRestrictions(merged,
                Arrays.asList(AccessControlConstants.REP_GLOB, AccessControlConstants.REP_ITEM_NAMES),
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));

        Set<Privilege> allowSet = merged.values().stream()
                .filter(lp -> lp.isAllow())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());

        assertEquals(2, allowSet.size());

        Set<LocalRestriction> readAllowRestrictions = 
                merged.get(priv(PrivilegeConstants.REP_READ_PROPERTIES)).getDenyRestrictions();
        assertTrue(readAllowRestrictions.isEmpty());
    }

    @Test
    public void testDenyRestriction() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        // deny jcr:read with restriction
        PrivilegesHelper.denyRestriction(merged,
                new LocalRestriction(rd(AccessControlConstants.REP_GLOB), val("/hello")),
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));

        // deny jcr:modifyProperties with restriction
        PrivilegesHelper.denyRestriction(merged,
                new LocalRestriction(rd(AccessControlConstants.REP_ITEM_NAMES), vals("item1", "item2")),
                Collections.singleton(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES)));

        Set<Privilege> denySet = merged.values().stream()
                .filter(lp -> lp.isDeny())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());

        assertEquals(5, denySet.size());

        Set<LocalRestriction> readDenyRestrictions = 
                merged.get(priv(PrivilegeConstants.REP_READ_PROPERTIES)).getDenyRestrictions();
        assertEquals(1, readDenyRestrictions.size());
        assertEquals(new LocalRestriction(rd(AccessControlConstants.REP_GLOB), val("/hello")),
                readDenyRestrictions.iterator().next());

        Set<LocalRestriction> modifyDenyRestrictions = 
                merged.get(priv(PrivilegeConstants.REP_ADD_PROPERTIES)).getDenyRestrictions();
        assertEquals(1, modifyDenyRestrictions.size());
        assertEquals(new LocalRestriction(rd(AccessControlConstants.REP_ITEM_NAMES), vals("item1", "item2")),
                modifyDenyRestrictions.iterator().next());
    }

    @Test
    public void testUndenyRestriction() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        // deny jcr:read with restriction
        PrivilegesHelper.denyRestriction(merged,
                new LocalRestriction(rd(AccessControlConstants.REP_GLOB), val("/hello")),
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));
        // deny jcr:modifyProperties with restriction
        PrivilegesHelper.denyRestriction(merged,
                new LocalRestriction(rd(AccessControlConstants.REP_ITEM_NAMES), vals("item1", "item2")),
                Collections.singleton(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES)));

        // undeny jcr:read with restriction
        PrivilegesHelper.undenyRestriction(merged, AccessControlConstants.REP_GLOB,
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));
        // undeny jcr:modifyProperties with restriction
        PrivilegesHelper.undenyRestriction(merged, AccessControlConstants.REP_ITEM_NAMES,
                Collections.singleton(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES)));

        Set<Privilege> denySet = merged.values().stream()
                .filter(lp -> lp.isDeny())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());

        assertEquals(5, denySet.size());

        Set<LocalRestriction> readDenyRestrictions =
                merged.get(priv(PrivilegeConstants.REP_READ_PROPERTIES)).getDenyRestrictions();
        assertTrue(readDenyRestrictions.isEmpty());

        Set<LocalRestriction> modifyDenyRestrictions =
                merged.get(priv(PrivilegeConstants.REP_ADD_PROPERTIES)).getDenyRestrictions();
        assertTrue(modifyDenyRestrictions.isEmpty());
    }

    @Test
    public void testUndenyRestrictionNotExists() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        // deny jcr:read with restriction
        PrivilegesHelper.denyRestriction(merged,
                new LocalRestriction(rd(AccessControlConstants.REP_GLOB), val("/hello")),
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));

        // undeny jcr:read with restriction that does note exist
        PrivilegesHelper.undenyRestriction(merged, AccessControlConstants.REP_ITEM_NAMES,
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));

        Set<Privilege> denySet = merged.values().stream()
                .filter(lp -> lp.isDeny())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());

        assertEquals(2, denySet.size());

        Set<LocalRestriction> readDenyRestrictions =
                merged.get(priv(PrivilegeConstants.REP_READ_PROPERTIES)).getDenyRestrictions();
        assertEquals(1, readDenyRestrictions.size());
        assertEquals(new LocalRestriction(rd(AccessControlConstants.REP_GLOB), val("/hello")),
                readDenyRestrictions.iterator().next());
    }

    @Test
    public void testUndenyRestrictions() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        // deny jcr:read with restriction
        PrivilegesHelper.denyRestriction(merged,
                new LocalRestriction(rd(AccessControlConstants.REP_GLOB), val("/hello")),
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));
        // deny jcr:read with restriction
        PrivilegesHelper.denyRestriction(merged,
                new LocalRestriction(rd(AccessControlConstants.REP_ITEM_NAMES), vals("item1", "item2")),
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));

        // undeny jcr:read with restriction
        PrivilegesHelper.undenyRestrictions(merged,
                Arrays.asList(AccessControlConstants.REP_GLOB, AccessControlConstants.REP_ITEM_NAMES),
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));

        Set<Privilege> denySet = merged.values().stream()
                .filter(lp -> lp.isDeny())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());

        assertEquals(2, denySet.size());

        Set<LocalRestriction> readDenyRestrictions =
                merged.get(priv(PrivilegeConstants.REP_READ_PROPERTIES)).getDenyRestrictions();
        assertTrue(readDenyRestrictions.isEmpty());
    }

    @Test
    public void testAllowOrDenyRestriction() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        PrivilegesHelper.allow(merged, Collections.emptySet(),
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));
        PrivilegesHelper.deny(merged, Collections.emptySet(),
                Collections.singleton(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES)));

        // allow jcr:read with restriction
        PrivilegesHelper.allowOrDenyRestriction(merged,
                new LocalRestriction(rd(AccessControlConstants.REP_GLOB), val("/hello")),
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));

        // deny jcr:modifyProperties with restriction
        PrivilegesHelper.allowOrDenyRestriction(merged,
                new LocalRestriction(rd(AccessControlConstants.REP_ITEM_NAMES), vals("item1", "item2")),
                Collections.singleton(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES)));

        Set<Privilege> allowSet = merged.values().stream()
                .filter(lp -> lp.isAllow())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());
        Set<Privilege> denySet = merged.values().stream()
                .filter(lp -> lp.isDeny())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());

        assertEquals(2, allowSet.size());
        assertEquals(3, denySet.size());

        Set<LocalRestriction> readAllowRestrictions =
                merged.get(priv(PrivilegeConstants.REP_READ_PROPERTIES)).getAllowRestrictions();
        assertEquals(1, readAllowRestrictions.size());
        assertEquals(new LocalRestriction(rd(AccessControlConstants.REP_GLOB), val("/hello")),
                readAllowRestrictions.iterator().next());

        Set<LocalRestriction> modifyDenyRestrictions =
                merged.get(priv(PrivilegeConstants.REP_ADD_PROPERTIES)).getDenyRestrictions();
        assertEquals(1, modifyDenyRestrictions.size());
        assertEquals(new LocalRestriction(rd(AccessControlConstants.REP_ITEM_NAMES), vals("item1", "item2")),
                modifyDenyRestrictions.iterator().next());
    }

    @Test
    public void testUnallowOrUndenyRestriction() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        PrivilegesHelper.allow(merged,
                Collections.singleton(new LocalRestriction(rd(AccessControlConstants.REP_GLOB), val("/hello"))),
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));
        PrivilegesHelper.deny(merged,
                Collections.singleton(new LocalRestriction(rd(AccessControlConstants.REP_ITEM_NAMES), vals("item1", "item2"))),
                Collections.singleton(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES)));

        // allow jcr:read with restriction
        PrivilegesHelper.unallowOrUndenyRestriction(merged, AccessControlConstants.REP_GLOB, 
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));

        // allow jcr:modifyProperties with restriction
        PrivilegesHelper.unallowOrUndenyRestriction(merged, AccessControlConstants.REP_ITEM_NAMES, 
                Collections.singleton(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES)));

        Set<Privilege> allowSet = merged.values().stream()
                .filter(lp -> lp.isAllow())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());
        Set<Privilege> denySet = merged.values().stream()
                .filter(lp -> lp.isDeny())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());

        assertEquals(2, allowSet.size());
        assertEquals(3, denySet.size());

        Set<LocalRestriction> readAllowRestrictions =
                merged.get(priv(PrivilegeConstants.REP_READ_PROPERTIES)).getAllowRestrictions();
        assertTrue(readAllowRestrictions.isEmpty());

        Set<LocalRestriction> modifyDenyRestrictions =
                merged.get(priv(PrivilegeConstants.REP_ADD_PROPERTIES)).getDenyRestrictions();
        assertTrue(modifyDenyRestrictions.isEmpty());
    }

    @Test
    public void testUnallowOrUndenyRestrictions() throws RepositoryException {
        Map<Privilege, LocalPrivilege> merged = new HashMap<>();

        Set<LocalRestriction> restrictions = new HashSet<>();
        restrictions.add(new LocalRestriction(rd(AccessControlConstants.REP_GLOB), val("/hello")));
        restrictions.add(new LocalRestriction(rd(AccessControlConstants.REP_ITEM_NAMES), vals("item1", "item2")));

        // allow jcr:read with restriction
        PrivilegesHelper.allow(merged, restrictions, Collections.singleton(priv(PrivilegeConstants.JCR_READ)));
        // allow jcr:modifyProperties with restriction
        PrivilegesHelper.deny(merged, restrictions, Collections.singleton(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES)));

        // unallow jcr:read restrictions
        PrivilegesHelper.unallowOrUndenyRestrictions(merged,
                Arrays.asList(AccessControlConstants.REP_GLOB, AccessControlConstants.REP_ITEM_NAMES),
                Collections.singleton(priv(PrivilegeConstants.JCR_READ)));
        // unallow jcr:modifyProperties restrictions
        PrivilegesHelper.unallowOrUndenyRestrictions(merged,
                Arrays.asList(AccessControlConstants.REP_GLOB, AccessControlConstants.REP_ITEM_NAMES),
                Collections.singleton(priv(PrivilegeConstants.JCR_MODIFY_PROPERTIES)));

        Set<Privilege> allowSet = merged.values().stream()
                .filter(lp -> lp.isAllow())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());
        Set<Privilege> denySet = merged.values().stream()
                .filter(lp -> lp.isDeny())
                .map(lp -> lp.getPrivilege())
                .collect(Collectors.toSet());

        assertEquals(2, allowSet.size());
        assertEquals(3, denySet.size());

        Set<LocalRestriction> readAllowRestrictions =
                merged.get(priv(PrivilegeConstants.REP_READ_PROPERTIES)).getAllowRestrictions();
        assertTrue(readAllowRestrictions.isEmpty());

        Set<LocalRestriction> modifyDenyRestrictions =
                merged.get(priv(PrivilegeConstants.REP_ADD_PROPERTIES)).getDenyRestrictions();
        assertTrue(modifyDenyRestrictions.isEmpty());
    }

}
