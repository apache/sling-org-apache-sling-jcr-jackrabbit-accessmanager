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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.jcr.RepositoryException;
import javax.jcr.Value;
import javax.jcr.ValueFactory;

import org.apache.jackrabbit.oak.security.authorization.restriction.RestrictionProviderImpl;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionDefinition;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.jackrabbit.value.ValueFactoryImpl;
import org.apache.sling.testing.mock.sling.ResourceResolverType;
import org.apache.sling.testing.mock.sling.junit.SlingContext;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

/**
 * Tests for {@link LocalRestriction}
 *
 */
public class LocalRestrictionTest {

    @Rule
    public final SlingContext context = new SlingContext(ResourceResolverType.JCR_OAK);

    private Map<String, RestrictionDefinition> srMap;

    @Before
    public void setup() throws RepositoryException {
        context.registerService(new RestrictionProviderImpl());
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
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalRestriction#hashCode()}.
     */
    @Test
    public void testHashCode() throws Exception {
        LocalRestriction lr1 = new LocalRestriction(rd("rep:glob"), val("/hello1"));
        LocalRestriction lr2 = new LocalRestriction(rd("rep:glob"), val("/hello2"));
        assertNotSame(lr1.hashCode(), lr2.hashCode());

        LocalRestriction lr3 = new LocalRestriction(rd("rep:glob"), val("/hello1"));
        assertEquals(lr1.hashCode(), lr3.hashCode());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalRestriction#getName()}.
     */
    @Test
    public void testGetName() throws Exception {
        LocalRestriction lr1 = new LocalRestriction(rd("rep:glob"), val("/hello1"));
        assertEquals("rep:glob", lr1.getName());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalRestriction#isMultiValue()}.
     */
    @Test
    public void testIsMultiValue() throws Exception {
        LocalRestriction lr1 = new LocalRestriction(rd("rep:glob"), val("/hello1"));
        assertFalse(lr1.isMultiValue());

        LocalRestriction lr2 = new LocalRestriction(rd("rep:itemNames"), vals("item1", "item2"));
        assertTrue(lr2.isMultiValue());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalRestriction#getValue()}.
     */
    @Test
    public void testGetValue() throws Exception {
        LocalRestriction lr1 = new LocalRestriction(rd("rep:glob"), val("/hello1"));
        assertEquals(val("/hello1"), lr1.getValue());

        LocalRestriction lr2 = new LocalRestriction(rd("rep:glob"), (Value)null);
        assertNull(lr2.getValue());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalRestriction#getValues()}.
     */
    @Test
    public void testGetValues() throws Exception {
        LocalRestriction lr2 = new LocalRestriction(rd("rep:itemNames"), vals("item1", "item2"));
        assertArrayEquals(vals("item1", "item2"), lr2.getValues());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalRestriction#toString()}.
     */
    @Test
    public void testToString() throws Exception {
        LocalRestriction lr1 = new LocalRestriction(rd("rep:glob"), val("/hello1"));
        assertNotNull(lr1.toString());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.LocalRestriction#equals(java.lang.Object)}.
     */
    @Test
    public void testEqualsObject() throws Exception {
        LocalRestriction lr1 = new LocalRestriction(rd("rep:glob"), val("/hello1"));
        assertEquals(lr1, lr1);
        assertNotEquals(lr1, null);
        assertNotEquals(lr1, this);

        LocalRestriction lr2 = new LocalRestriction(rd("rep:glob"), val("/hello2"));
        assertNotEquals(lr1, lr2);

        LocalRestriction lr3 = new LocalRestriction(rd("rep:glob"), val("/hello1"));
        assertEquals(lr1, lr3);
    }

}