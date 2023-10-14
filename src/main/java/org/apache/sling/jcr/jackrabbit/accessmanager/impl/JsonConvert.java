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

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.Principal;
import java.util.Collection;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.jcr.PropertyType;
import javax.jcr.RepositoryException;
import javax.jcr.Value;
import javax.jcr.security.Privilege;
import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObjectBuilder;

import org.apache.sling.jcr.jackrabbit.accessmanager.LocalPrivilege;
import org.apache.sling.jcr.jackrabbit.accessmanager.LocalRestriction;
import org.apache.sling.jcr.jackrabbit.accessmanager.post.DeclarationType;

/**
 * Utilities to help convert ACL/ACE data to JSON
 */
public class JsonConvert {
    public static final String KEY_PRINCIPAL = "principal";
    public static final String KEY_ORDER = "order";
    public static final String KEY_PRIVILEGES = "privileges";
    public static final String KEY_ALLOW = "allow";
    public static final String KEY_DENY = "deny";
    public static final String KEY_DECLARED_AT = "declaredAt";

    private JsonConvert() {
        // no-op
    }

    public static JsonObjectBuilder convertToJson(Principal principal, Map<Privilege, LocalPrivilege> entry,
            int order) {
        JsonObjectBuilder principalObj = Json.createObjectBuilder();
        principalObj.add(JsonConvert.KEY_PRINCIPAL, principal.getName());
        if (order != -1) {
            principalObj.add(JsonConvert.KEY_ORDER, order);
        }
        Collection<LocalPrivilege> privileges = entry.values();
        if (!privileges.isEmpty()) {
            JsonObjectBuilder privilegesObj = Json.createObjectBuilder();
            for (LocalPrivilege pi : privileges) {
                if (pi.isNone()) {
                    continue;
                }
                JsonObjectBuilder privilegeObj = Json.createObjectBuilder();

                if (pi.isAllow()) {
                    JsonConvert.addRestrictions(privilegeObj, JsonConvert.KEY_ALLOW, pi.getAllowRestrictions());
                }
                if (pi.isDeny()) {
                    JsonConvert.addRestrictions(privilegeObj, JsonConvert.KEY_DENY, pi.getDenyRestrictions());
                }
                privilegesObj.add(pi.getName(), privilegeObj);
            }
            principalObj.add(JsonConvert.KEY_PRIVILEGES, privilegesObj);
        }
        return principalObj;
    }

    /**
     * Add details about where the privileges were declared, usually
     * for viewing the effective access list or entry
     */
    public static void addDeclaredAt(JsonObjectBuilder principalObj, Map<DeclarationType, Set<String>> declaredAt) {
        JsonObjectBuilder declaredAtBuilder = Json.createObjectBuilder();
        for (Entry<DeclarationType, Set<String>> daentry : declaredAt.entrySet()) {
            DeclarationType type = daentry.getKey();
            if (type != null) {
                Set<String> value = daentry.getValue();
                if (value.size() == 1) {
                    declaredAtBuilder.add(type.getJsonKey(), value.iterator().next());
                } else {
                    JsonArrayBuilder typeBuilder = Json.createArrayBuilder();
                    for (String at : value) {
                        typeBuilder.add(at);
                    }
                    declaredAtBuilder.add(type.getJsonKey(), typeBuilder);
                }
            }
        }
        principalObj.add(JsonConvert.KEY_DECLARED_AT, declaredAtBuilder);
    }

    public static void addRestrictions(JsonObjectBuilder privilegeObj, String key, Set<LocalRestriction> restrictions) {
        if (restrictions.isEmpty()) {
            privilegeObj.add(key, true);
        } else {
            JsonObjectBuilder allowObj = Json.createObjectBuilder();
            for (LocalRestriction ri : restrictions) {
                if (ri.isMultiValue()) {
                    JsonArrayBuilder rvalues = Json.createArrayBuilder();
                    for (Value value: ri.getValues()) {
                        addTo(rvalues, value);
                    }
                    allowObj.add(ri.getName(), rvalues);
                } else {
                    addTo(allowObj, ri.getName(), ri.getValue());
                }
            }
            privilegeObj.add(key, allowObj);
        }
    }

    public static JsonObjectBuilder addTo(JsonObjectBuilder builder, String key, Object value) {
        value = convertJcrValue(value);
        if (value instanceof Byte || value instanceof Short || value instanceof Integer || value instanceof Long) {
            builder.add(key, ((Number) value).longValue());
        } else if (value instanceof BigDecimal) {
            builder.add(key, (BigDecimal) value);
        } else if (value instanceof BigInteger) {
            builder.add(key, (BigInteger) value);
        } else if (value instanceof Boolean) {
            builder.add(key, (Boolean) value);
        } else if (value instanceof Float || value instanceof Double) {
            builder.add(key, ((Number) value).doubleValue());
        } else if (value instanceof Privilege) {
            JsonObjectBuilder privilegeBuilder = Json.createObjectBuilder();
            privilegeBuilder.add("name", ((Privilege) value).getName());
            builder.add(key, privilegeBuilder);
        } else if (value instanceof String) {
            builder.add(key, (String) value);
        } else {
            builder.add(key, value.toString());
        }
        return builder;
    }

    public static JsonArrayBuilder addTo(JsonArrayBuilder builder, Object value) {
        value = convertJcrValue(value);
        if (value instanceof Byte || value instanceof Short || value instanceof Integer || value instanceof Long) {
            builder.add(((Number) value).longValue());
        } else if (value instanceof BigDecimal) {
            builder.add((BigDecimal) value);
        } else if (value instanceof BigInteger) {
            builder.add((BigInteger) value);
        } else if (value instanceof Boolean) {
            builder.add((Boolean) value);
        } else if (value instanceof Float || value instanceof Double) {
            builder.add(((Number) value).doubleValue());
        } else if (value instanceof String) {
            builder.add((String) value);
        } else {
            builder.add(value.toString());
        }
        return builder;
    }

    private static Object convertJcrValue(Object value) {
        if (value instanceof Value) {
            try {
                Value jcrValue = (Value)value;
                int valueType = jcrValue.getType();
                if (valueType == PropertyType.DOUBLE) {
                    value = jcrValue.getDouble();
                } else if (valueType == PropertyType.DECIMAL) {
                    value = jcrValue.getDecimal();
                } else if (valueType == PropertyType.LONG) {
                    value = jcrValue.getLong();
                } else if (valueType == PropertyType.BOOLEAN) {
                    value = jcrValue.getBoolean();
                } else {
                    value = jcrValue.getString();
                }
            } catch (RepositoryException re) {
                // should never get here
            }
        }
        return value;
    }

}
