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
package org.apache.sling.jcr.jackrabbit.accessmanager.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.Value;
import javax.jcr.ValueFactory;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.Privilege;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;

import org.apache.jackrabbit.oak.security.authorization.restriction.RestrictionProviderImpl;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.AccessControlConstants;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.CompositeRestrictionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionDefinition;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.jackrabbit.oak.spi.security.principal.PrincipalImpl;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.jackrabbit.value.ValueFactoryImpl;
import org.apache.sling.jcr.jackrabbit.accessmanager.LocalPrivilege;
import org.apache.sling.jcr.jackrabbit.accessmanager.LocalRestriction;
import org.apache.sling.testing.mock.sling.ResourceResolverType;
import org.apache.sling.testing.mock.sling.junit.SlingContext;
import org.jetbrains.annotations.NotNull;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

/**
 *
 */
public class JsonConvertTest {

    @Rule
    public final SlingContext context = new SlingContext(ResourceResolverType.JCR_OAK);

    private AccessControlManager acm;

    private Map<String, RestrictionDefinition> srMap;

    @Before
    public void buildPrivilegesMap() throws RepositoryException {
        context.registerService(new RestrictionProviderImpl());
        Session session = context.resourceResolver().adaptTo(Session.class);
        acm = session.getAccessControlManager();
    }

    private Privilege priv(String privilegeName) throws RepositoryException {
        return acm.privilegeFromName(privilegeName);
    }

    private RestrictionDefinition rd(String restrictionName) {
        if (srMap == null) {
            //make a temp map for quick lookup below
            @NotNull
            RestrictionProvider[] services = context.getServices(RestrictionProvider.class, null);
            RestrictionProvider restrictionProvider = CompositeRestrictionProvider.newInstance(services);
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
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.impl.JsonConvert#convertToJson(java.security.Principal, java.util.Map, int)}.
     */
    @Test
    public void testConvertToJson() throws RepositoryException {
        Principal principal = new PrincipalImpl("testuser");
        LocalPrivilege lp1 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ));
        lp1.setAllow(true);
        LocalPrivilege lp2 = new LocalPrivilege(priv(PrivilegeConstants.JCR_WRITE));
        lp2.setDeny(true);
        LocalPrivilege lp3 = new LocalPrivilege(priv(PrivilegeConstants.JCR_READ_ACCESS_CONTROL));
        LocalPrivilege lp4 = new LocalPrivilege(priv(PrivilegeConstants.JCR_NODE_TYPE_MANAGEMENT));
        lp4.setAllow(true);
        lp4.setAllowRestrictions(Collections.singleton(new LocalRestriction(rd(AccessControlConstants.REP_GLOB), val("/hello"))));
        LocalPrivilege lp5 = new LocalPrivilege(priv(PrivilegeConstants.JCR_MODIFY_ACCESS_CONTROL));
        lp5.setDeny(true);
        lp5.setDenyRestrictions(Collections.singleton(new LocalRestriction(rd(AccessControlConstants.REP_ITEM_NAMES), vals("item1", "item2"))));
        Map<Privilege, LocalPrivilege> entry = new HashMap<>();
        entry.put(lp1.getPrivilege(), lp1);
        entry.put(lp2.getPrivilege(), lp2);
        entry.put(lp3.getPrivilege(), lp3);
        entry.put(lp4.getPrivilege(), lp4);
        entry.put(lp5.getPrivilege(), lp5);
        int order = 1;
        JsonObjectBuilder principalObj = JsonConvert.convertToJson(principal, entry, order);
        assertNotNull(principalObj);
        JsonObject build = principalObj.build();
        assertEquals("testuser", build.getString(JsonConvert.KEY_PRINCIPAL));
        assertEquals(1, build.getInt(JsonConvert.KEY_ORDER));
        JsonObject privilegesObj = build.getJsonObject(JsonConvert.KEY_PRIVILEGES);
        assertNotNull(privilegesObj);
        assertEquals(4, privilegesObj.size());

        JsonValue jsonValue1 = privilegesObj.get(PrivilegeConstants.JCR_READ);
        assertTrue(jsonValue1 instanceof JsonObject);
        assertTrue(((JsonObject)jsonValue1).getBoolean(JsonConvert.KEY_ALLOW));

        JsonValue jsonValue2 = privilegesObj.get(PrivilegeConstants.JCR_WRITE);
        assertTrue(jsonValue2 instanceof JsonObject);
        assertTrue(((JsonObject)jsonValue2).getBoolean(JsonConvert.KEY_DENY));

        JsonValue jsonValue4 = privilegesObj.get(PrivilegeConstants.JCR_NODE_TYPE_MANAGEMENT);
        assertTrue(jsonValue4 instanceof JsonObject);
        JsonObject allowObj4 = ((JsonObject)jsonValue4).getJsonObject(JsonConvert.KEY_ALLOW);
        assertNotNull(allowObj4);
        Object globRestrictionObj4 = allowObj4.get(AccessControlConstants.REP_GLOB);
        assertTrue(globRestrictionObj4 instanceof JsonString);
        assertEquals("/hello", ((JsonString)globRestrictionObj4).getString());

        JsonValue jsonValue5 = privilegesObj.get(PrivilegeConstants.JCR_MODIFY_ACCESS_CONTROL);
        assertTrue(jsonValue5 instanceof JsonObject);
        JsonObject allowObj5 = ((JsonObject)jsonValue5).getJsonObject(JsonConvert.KEY_DENY);
        assertNotNull(allowObj5);
        Object itemNamesRestrictionObj5 = allowObj5.get(AccessControlConstants.REP_ITEM_NAMES);
        assertTrue(itemNamesRestrictionObj5 instanceof JsonArray);
        assertEquals("item1", ((JsonArray)itemNamesRestrictionObj5).getString(0));
        assertEquals("item2", ((JsonArray)itemNamesRestrictionObj5).getString(1));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.impl.JsonConvert#addRestrictions(jakarta.json.JsonObjectBuilder, java.lang.String, java.util.Set)}.
     */
    @Test
    public void testAddRestrictions() {
        JsonObjectBuilder privilegeObj = Json.createObjectBuilder();
        String key = JsonConvert.KEY_ALLOW;
        Set<LocalRestriction> restrictions = new HashSet<>();
        restrictions.add(new LocalRestriction(rd(AccessControlConstants.REP_GLOB), val("/hello")));
        restrictions.add(new LocalRestriction(rd(AccessControlConstants.REP_ITEM_NAMES), vals("item1", "item2")));
        JsonConvert.addRestrictions(privilegeObj, key, restrictions);
        JsonObject build = privilegeObj.build();
        assertNotNull(build);
        JsonObject allowObj = build.getJsonObject(JsonConvert.KEY_ALLOW);
        assertNotNull(allowObj);
        Object globRestrictionObj = allowObj.get(AccessControlConstants.REP_GLOB);
        assertTrue(globRestrictionObj instanceof JsonString);
        assertEquals("/hello", ((JsonString)globRestrictionObj).getString());
        Object itemNamesRestrictionObj = allowObj.get(AccessControlConstants.REP_ITEM_NAMES);
        assertTrue(itemNamesRestrictionObj instanceof JsonArray);
        assertEquals("item1", ((JsonArray)itemNamesRestrictionObj).getString(0));
        assertEquals("item2", ((JsonArray)itemNamesRestrictionObj).getString(1));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.impl.JsonConvert#addTo(jakarta.json.JsonObjectBuilder, java.lang.String, java.lang.Object)}.
     */
    @Test
    public void testAddToJsonObjectBuilderStringObject() throws RepositoryException {
        String key = JsonConvert.KEY_ALLOW;
        Function<JsonObject, Object> doubleFn = json -> json.getJsonNumber(key).doubleValue();
        Function<JsonObject, Object> bigDecimalFn = json -> json.getJsonNumber(key).bigDecimalValue();
        Function<JsonObject, Object> bigIntegerFn = json -> json.getJsonNumber(key).bigIntegerValue();
        Function<JsonObject, Object> longFn = json -> json.getJsonNumber(key).longValue();
        Function<JsonObject, Object> intFn = json -> json.getJsonNumber(key).intValue();
        Function<JsonObject, Object> booleanFn = json -> json.getBoolean(key);
        Function<JsonObject, Object> stringFn = json -> json.getString(key);
        Function<JsonObject, Object> privFn = json -> json.getJsonObject(key).getString("name");

        ValueFactory vf = ValueFactoryImpl.getInstance();
        // data to test [label, value, expectedValueFromJson, lookupFromJsonFn]
        Object[][] candidates = new Object[][] {
            // JCR Value types
            {"JCR double Value", vf.createValue((double)1.1), 1.1, doubleFn},
            {"JCR BigDecimal Value", vf.createValue(new BigDecimal("1.1")), new BigDecimal("1.1"), bigDecimalFn},
            {"JCR long Value", vf.createValue(1L), 1L, longFn},
            {"JCR boolean Value", vf.createValue(true), true, booleanFn},
            {"JCR string Value", vf.createValue("hello"), "hello", stringFn},

            // non-JCR values
            {"byte value", (byte)1, 1, intFn},
            {"short value", (short)1, 1, intFn},
            {"int value", 1, 1, intFn},
            {"long value", 1L, 1L, longFn},
            {"BigDecimal value", new BigDecimal("1.1"), new BigDecimal("1.1"), bigDecimalFn},
            {"BigInteger value", new BigInteger("1"), new BigInteger("1"), bigIntegerFn},
            {"true boolean value", true, true, booleanFn},
            {"false boolean value", false, false, booleanFn},
            {"float value", (float)1.1, (double)1.1, doubleFn},
            {"double value", 1.1, 1.1, doubleFn},
            {"string value", "hello", "hello", stringFn},
            {"privilege value", priv(PrivilegeConstants.JCR_READ), PrivilegeConstants.JCR_READ, privFn},
            {"object value", new StringBuilder().append("hello"), "hello", stringFn}
        };
        for (Object[] objects : candidates) {
            Object value = objects[1];
            JsonObjectBuilder builder = Json.createObjectBuilder();
            JsonConvert.addTo(builder, key, value);
            JsonObject build = builder.build();
            assertNotNull(build);
            assertEquals(1, build.size());
            @SuppressWarnings("unchecked")
            Function<JsonObject, Object> supplier = (Function<JsonObject, Object>)objects[3];
            if (objects[2] instanceof Double) {
                double epsilon = 0.000001d;
                assertEquals(String.format("%s was not the expected value", objects[0]), (double)objects[2], (double)supplier.apply(build), epsilon);
            } else {
                assertEquals(String.format("%s was not the expected value", objects[0]), objects[2], supplier.apply(build));
            }
        }
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.impl.JsonConvert#addTo(jakarta.json.JsonArrayBuilder, java.lang.Object)}.
     */
    @Test
    public void testAddToJsonArrayBuilderObject() {
        Function<JsonArray, Object> doubleFn = json -> json.getJsonNumber(0).doubleValue();
        Function<JsonArray, Object> bigDecimalFn = json -> json.getJsonNumber(0).bigDecimalValue();
        Function<JsonArray, Object> bigIntegerFn = json -> json.getJsonNumber(0).bigIntegerValue();
        Function<JsonArray, Object> longFn = json -> json.getJsonNumber(0).longValue();
        Function<JsonArray, Object> intFn = json -> json.getJsonNumber(0).intValue();
        Function<JsonArray, Object> booleanFn = json -> json.getBoolean(0);
        Function<JsonArray, Object> stringFn = json -> json.getString(0);

        ValueFactory vf = ValueFactoryImpl.getInstance();
        // data to test [label, value, expectedValueFromJson, lookupFromJsonFn]
        Object[][] candidates = new Object[][] {
            // JCR Value types
            {"JCR double Value", vf.createValue((double)1.1), 1.1, doubleFn},
            {"JCR BigDecimal Value", vf.createValue(new BigDecimal("1.1")), new BigDecimal("1.1"), bigDecimalFn},
            {"JCR long Value", vf.createValue(1L), 1L, longFn},
            {"JCR boolean Value", vf.createValue(true), true, booleanFn},
            {"JCR string Value", vf.createValue("hello"), "hello", stringFn},

            // non-JCR values
            {"byte value", (byte)1, 1, intFn},
            {"short value", (short)1, 1, intFn},
            {"int value", 1, 1, intFn},
            {"long value", 1L, 1L, longFn},
            {"BigDecimal value", new BigDecimal("1.1"), new BigDecimal("1.1"), bigDecimalFn},
            {"BigInteger value", new BigInteger("1"), new BigInteger("1"), bigIntegerFn},
            {"true boolean value", true, true, booleanFn},
            {"false boolean value", false, false, booleanFn},
            {"float value", (float)1.1, (double)1.1, doubleFn},
            {"double value", 1.1, 1.1, doubleFn},
            {"string value", "hello", "hello", stringFn},
            {"object value", new StringBuilder().append("hello"), "hello", stringFn}
        };
        for (Object[] objects : candidates) {
            Object value = objects[1];
            JsonArrayBuilder builder = Json.createArrayBuilder();
            JsonConvert.addTo(builder, value);
            JsonArray build = builder.build();
            assertNotNull(build);
            assertEquals(1, build.size());
            @SuppressWarnings("unchecked")
            Function<JsonArray, Object> supplier = (Function<JsonArray, Object>)objects[3];
            if (objects[2] instanceof Double) {
                double epsilon = 0.000001d;
                assertEquals(String.format("%s was not the expected value", objects[0]), (double)objects[2], (double)supplier.apply(build), epsilon);
            } else {
                assertEquals(String.format("%s was not the expected value", objects[0]), objects[2], supplier.apply(build));
            }
        }
    }

}
