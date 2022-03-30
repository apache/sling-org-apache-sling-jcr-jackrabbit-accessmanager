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
package org.apache.sling.jcr.jackrabbit.accessmanager.post;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.Value;
import javax.jcr.ValueFactory;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.Privilege;

import org.apache.jackrabbit.oak.security.authorization.restriction.RestrictionProviderImpl;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionDefinition;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.jackrabbit.value.ValueFactoryImpl;
import org.apache.sling.jcr.base.util.AccessControlUtil;
import org.apache.sling.testing.mock.sling.ResourceResolverType;
import org.apache.sling.testing.mock.sling.junit.SlingContext;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

/**
 * Tests for {@link LocalPrivilege}
 */
public class LocalPrivilegeTest {

    @Rule
    public final SlingContext context = new SlingContext(ResourceResolverType.JCR_OAK);

    private AccessControlManager acm;
    private Map<String, RestrictionDefinition> srMap;

    @Before
    public void setup() throws RepositoryException {
        Session session = context.resourceResolver().adaptTo(Session.class);
        acm = AccessControlUtil.getAccessControlManager(session);
        context.registerService(new RestrictionProviderImpl());
    }

    private Privilege priv(String privilegeName) throws RepositoryException {
        return acm.privilegeFromName(privilegeName);
    }

    private RestrictionDefinition rd(String restrictionName) throws Exception {
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

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalPrivilege#hashCode()}.
     */
    @Test
    public void testHashCode() throws RepositoryException {
        LocalPrivilege lp1 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        LocalPrivilege lp2 = new LocalPrivilege(priv(PrivilegeConstants.JCR_WRITE));
        assertNotEquals(lp1.hashCode(), lp2.hashCode());

        LocalPrivilege lp3 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        assertEquals(lp1.hashCode(), lp3.hashCode());

        LocalPrivilege lp4 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        lp4.setAllow(true);
        assertNotEquals(lp1.hashCode(), lp4.hashCode());
        lp4.setDeny(true);
        assertNotEquals(lp1.hashCode(), lp4.hashCode());
        lp4.setAllowRestrictions(null);
        assertNotEquals(lp1.hashCode(), lp4.hashCode());
        lp4.setDenyRestrictions(null);
        assertNotEquals(lp1.hashCode(), lp4.hashCode());

        LocalPrivilege lp5 = new LocalPrivilege(null);
        assertNotEquals(lp1.hashCode(), lp5.hashCode());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalPrivilege#getPrivilege()}.
     */
    @Test
    public void testGetPrivilege() throws RepositoryException {
        LocalPrivilege lp1 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        assertEquals(priv(PrivilegeConstants.JCR_READ), lp1.getPrivilege());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalPrivilege#getName()}.
     */
    @Test
    public void testGetName() throws RepositoryException {
        LocalPrivilege lp1 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        assertEquals(PrivilegeConstants.JCR_READ, lp1.getName());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalPrivilege#isNone()}.
     */
    @Test
    public void testIsNone() throws RepositoryException {
        LocalPrivilege lp1 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        assertTrue(lp1.isNone());

        // deny set, allow not set
        lp1.setDeny(true);
        assertFalse(lp1.isNone());

        // allow set, deny set
        lp1.setAllow(true);
        assertFalse(lp1.isNone());

        // deny not set, allow set
        lp1.setDeny(false);
        assertFalse(lp1.isNone());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalPrivilege#isAllow()}.
     */
    @Test
    public void testIsAllow() throws RepositoryException {
        LocalPrivilege lp1 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        assertFalse(lp1.isAllow());

        lp1.setAllow(true);
        assertTrue(lp1.isAllow());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalPrivilege#isDeny()}.
     */
    @Test
    public void testIsDeny() throws RepositoryException {
        LocalPrivilege lp1 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        assertFalse(lp1.isDeny());

        lp1.setDeny(true);
        assertTrue(lp1.isDeny());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalPrivilege#getAllowRestrictions()}.
     */
    @Test
    public void testGetAllowRestrictions() throws Exception {
        LocalPrivilege lp1 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        Set<LocalRestriction> allowRestrictions = lp1.getAllowRestrictions();
        assertNotNull(allowRestrictions);
        assertTrue(allowRestrictions.isEmpty());

        Set<LocalRestriction> newAllowRestrictions = new HashSet<>();
        newAllowRestrictions.add(new LocalRestriction(rd("rep:glob"), val("/hello")));
        lp1.setAllowRestrictions(newAllowRestrictions);
        Set<LocalRestriction> allowRestrictions2 = lp1.getAllowRestrictions();
        assertNotNull(allowRestrictions2);
        assertFalse(allowRestrictions2.isEmpty());
        assertEquals(newAllowRestrictions, allowRestrictions2);
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalPrivilege#getDenyRestrictions()}.
     */
    @Test
    public void testGetDenyRestrictions() throws Exception {
        LocalPrivilege lp1 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        Set<LocalRestriction> denyRestrictions = lp1.getDenyRestrictions();
        assertNotNull(denyRestrictions);
        assertTrue(denyRestrictions.isEmpty());

        Set<LocalRestriction> newDenyRestrictions = new HashSet<>();
        newDenyRestrictions.add(new LocalRestriction(rd("rep:glob"), val("/hello")));
        lp1.setDenyRestrictions(newDenyRestrictions);
        Set<LocalRestriction> denyRestrictions2 = lp1.getDenyRestrictions();
        assertNotNull(denyRestrictions2);
        assertFalse(denyRestrictions2.isEmpty());
        assertEquals(newDenyRestrictions, denyRestrictions2);
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalPrivilege#sameAllowRestrictions(org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalPrivilege)}.
     */
    @Test
    public void testSameAllowRestrictions() throws Exception {
        LocalPrivilege lp1 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        LocalPrivilege lp2 = new LocalPrivilege(priv(PrivilegeConstants.JCR_WRITE));
        assertTrue(lp1.sameAllowRestrictions(lp2));

        Set<LocalRestriction> newAllowRestrictions1 = new HashSet<>();
        newAllowRestrictions1.add(new LocalRestriction(rd("rep:glob"), val("/hello")));
        newAllowRestrictions1.add(new LocalRestriction(rd("nt:itemNames"), vals("item1", "item2")));
        lp1.setAllowRestrictions(newAllowRestrictions1);
        assertFalse(lp1.sameAllowRestrictions(lp2));

        Set<LocalRestriction> newAllowRestrictions2 = new HashSet<>();
        newAllowRestrictions2.add(new LocalRestriction(rd("rep:glob"), val("/hello")));
        newAllowRestrictions2.add(new LocalRestriction(rd("nt:itemNames"), vals("item1", "item2")));
        lp2.setAllowRestrictions(newAllowRestrictions2);
        assertTrue(lp1.sameAllowRestrictions(lp2));

        Set<LocalRestriction> newAllowRestrictions3 = new HashSet<>();
        newAllowRestrictions3.add(new LocalRestriction(rd("rep:glob"), val("/hello")));
        newAllowRestrictions3.add(new LocalRestriction(rd("nt:itemNames"), vals("item1", "item2_changed")));
        lp2.setAllowRestrictions(newAllowRestrictions3);
        assertFalse(lp1.sameAllowRestrictions(lp2));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalPrivilege#sameDenyRestrictions(org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalPrivilege)}.
     */
    @Test
    public void testSameDenyRestrictions() throws Exception {
        LocalPrivilege lp1 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        LocalPrivilege lp2 = new LocalPrivilege(priv(PrivilegeConstants.JCR_WRITE));
        assertTrue(lp1.sameDenyRestrictions(lp2));

        Set<LocalRestriction> newDenyRestrictions1 = new HashSet<>();
        newDenyRestrictions1.add(new LocalRestriction(rd("rep:glob"), val("/hello")));
        newDenyRestrictions1.add(new LocalRestriction(rd("nt:itemNames"), vals("item1", "item2")));
        lp1.setDenyRestrictions(newDenyRestrictions1);
        assertFalse(lp1.sameDenyRestrictions(lp2));

        Set<LocalRestriction> newDenyRestrictions2 = new HashSet<>();
        newDenyRestrictions2.add(new LocalRestriction(rd("rep:glob"), val("/hello")));
        newDenyRestrictions2.add(new LocalRestriction(rd("nt:itemNames"), vals("item1", "item2")));
        lp2.setDenyRestrictions(newDenyRestrictions2);
        assertTrue(lp1.sameDenyRestrictions(lp2));

        Set<LocalRestriction> newDenyRestrictions3 = new HashSet<>();
        newDenyRestrictions3.add(new LocalRestriction(rd("rep:glob"), val("/hello")));
        newDenyRestrictions3.add(new LocalRestriction(rd("nt:itemNames"), vals("item1", "item2_changed")));
        lp2.setDenyRestrictions(newDenyRestrictions3);
        assertFalse(lp1.sameDenyRestrictions(lp2));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalPrivilege#sameAllowAndDenyRestrictions()}.
     */
    @Test
    public void testSameAllowAndDenyRestrictions() throws Exception {
        LocalPrivilege lp1 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        assertTrue(lp1.sameAllowAndDenyRestrictions());

        Set<LocalRestriction> newDenyRestrictions1 = new HashSet<>();
        newDenyRestrictions1.add(new LocalRestriction(rd("rep:glob"), val("/hello")));
        newDenyRestrictions1.add(new LocalRestriction(rd("nt:itemNames"), vals("item1", "item2")));
        lp1.setDenyRestrictions(newDenyRestrictions1);
        assertFalse(lp1.sameAllowAndDenyRestrictions());

        Set<LocalRestriction> newAllowRestrictions1 = new HashSet<>();
        newAllowRestrictions1.add(new LocalRestriction(rd("rep:glob"), val("/hello")));
        newAllowRestrictions1.add(new LocalRestriction(rd("nt:itemNames"), vals("item1", "item2")));
        lp1.setAllowRestrictions(newAllowRestrictions1);
        assertTrue(lp1.sameAllowAndDenyRestrictions());

        Set<LocalRestriction> newAllowRestrictions2 = new HashSet<>();
        newAllowRestrictions2.add(new LocalRestriction(rd("rep:glob"), val("/hello")));
        newAllowRestrictions2.add(new LocalRestriction(rd("nt:itemNames"), vals("item1", "item2_changed")));
        lp1.setAllowRestrictions(newAllowRestrictions2);
        assertFalse(lp1.sameAllowAndDenyRestrictions());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalPrivilege#toString()}.
     */
    @Test
    public void testToString() throws RepositoryException {
        LocalPrivilege lp1 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        assertNotNull(lp1.toString());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalPrivilege#equals(java.lang.Object)}.
     */
    @Test
    public void testEqualsObject() throws Exception {
        LocalPrivilege lp1 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        assertEquals(lp1, lp1);
        assertNotEquals(lp1, null);
        assertNotEquals(lp1, this);

        LocalPrivilege lp2 = new LocalPrivilege(priv(PrivilegeConstants.JCR_WRITE));
        assertNotEquals(lp1, lp2);

        LocalPrivilege lp3 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        assertEquals(lp1, lp3);

        LocalPrivilege lp4 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        lp4.setAllow(true);
        assertNotEquals(lp1, lp4);

        LocalPrivilege lp5 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        lp5.setDeny(true);
        assertNotEquals(lp1, lp5);

        LocalPrivilege lp6 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        lp6.setAllowRestrictions(null);
        assertNotEquals(lp1, lp6);

        LocalPrivilege lp7 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        lp7.setDenyRestrictions(null);
        assertNotEquals(lp1, lp7);

        LocalPrivilege lp8 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        lp8.setAllowRestrictions(null);
        LocalPrivilege lp9 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        assertNotEquals(lp8, lp9);

        LocalPrivilege lp10 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        lp10.setDenyRestrictions(null);
        LocalPrivilege lp11 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        assertNotEquals(lp10, lp11);

        LocalPrivilege lp12 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        lp12.setAllowRestrictions(new HashSet<>(Arrays.asList(new LocalRestriction(rd("rep:glob"), val("/hello")))));
        LocalPrivilege lp13 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        assertNotEquals(lp12, lp13);

        LocalPrivilege lp14 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        lp14.setDenyRestrictions(new HashSet<>(Arrays.asList(new LocalRestriction(rd("rep:glob"), val("/hello")))));
        LocalPrivilege lp15 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        assertNotEquals(lp14, lp15);

        LocalPrivilege lp16 = new LocalPrivilege(null);
        LocalPrivilege lp17 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        assertNotEquals(lp16, lp17);

        LocalPrivilege lp18 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        LocalPrivilege lp19 = new LocalPrivilege(null);
        assertNotEquals(lp18, lp19);

        LocalPrivilege lp20 = new LocalPrivilege(null);
        LocalPrivilege lp21 = new LocalPrivilege(null);
        assertEquals(lp20, lp21);
    }

}
