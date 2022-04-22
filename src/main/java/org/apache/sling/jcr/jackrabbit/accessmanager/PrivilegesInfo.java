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
package org.apache.sling.jcr.jackrabbit.accessmanager;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.jcr.Node;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.Value;
import javax.jcr.ValueFactory;
import javax.jcr.ValueFormatException;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.Privilege;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.json.JsonValue.ValueType;

import org.apache.jackrabbit.api.security.principal.PrincipalManager;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionDefinition;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.sling.jcr.base.util.AccessControlUtil;
import org.apache.sling.jcr.jackrabbit.accessmanager.impl.JsonConvert;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.FrameworkUtil;
import org.osgi.framework.ServiceReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Helper class to assist in the usage of access control from scripts.
 */
public class PrivilegesInfo {
    private Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Return the supported Privileges for the specified node.
     * 
     * @param node the node to check
     * @return array of Privileges
     * @throws RepositoryException if any errors reading the information
     */
    public Privilege [] getSupportedPrivileges(Node node) throws RepositoryException {
        return getSupportedPrivileges(node.getSession(), node.getPath());
    }

    /**
     * Returns the supported privileges for the specified path.
     * 
     * @param session the session for the current user
     * @param absPath the path to get the privileges for
     * @return array of Privileges
     * @throws RepositoryException if any errors reading the information
     */
    public Privilege [] getSupportedPrivileges(Session session, String absPath) throws RepositoryException {
        AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);
        return accessControlManager.getSupportedPrivileges(absPath);
    }

    /**
     * Wrapper class that holds the set of Privileges that are granted 
     * and/or denied for a specific principal.
     */
    public static class AccessRights {
        private Set<Privilege> granted = new HashSet<>();
        private Set<Privilege> denied = new HashSet<>();

        private ResourceBundle resBundle = null;
        private ResourceBundle getResourceBundle(Locale locale) {
            if (resBundle == null || !resBundle.getLocale().equals(locale)) {
                resBundle = ResourceBundle.getBundle(getClass().getPackage().getName() + ".PrivilegesResources", locale);
            }
            return resBundle;
        }

        public Set<Privilege> getGranted() {
            return granted;
        }
        public Set<Privilege> getDenied() {
            return denied;
        }

        public String getPrivilegeSetDisplayName(Locale locale) {
            if (denied != null && !denied.isEmpty()) {
                //if there are any denied privileges, then this is a custom privilege set
                return getResourceBundle(locale).getString("privilegeset.custom");
            } else {
                if (granted.isEmpty()) {
                    //appears to have an empty privilege set
                    return getResourceBundle(locale).getString("privilegeset.none");
                }

                if (granted.size() == 1) {
                    //check if the single privilege is jcr:all or jcr:read
                    Iterator<Privilege> iterator = granted.iterator();
                    Privilege next = iterator.next();
                    if (PrivilegeConstants.JCR_ALL.equals(next.getName())) {
                        //full control privilege set
                        return getResourceBundle(locale).getString("privilegeset.all");
                    } else if (PrivilegeConstants.JCR_READ.equals(next.getName())) {
                        //readonly privilege set
                        return getResourceBundle(locale).getString("privilegeset.readonly");
                    }
                } else if (granted.size() == 2) {
                    //check if the two privileges are jcr:read and jcr:write
                    Iterator<Privilege> iterator = granted.iterator();
                    Privilege next = iterator.next();
                    Privilege next2 = iterator.next();
                    if ( (PrivilegeConstants.JCR_READ.equals(next.getName()) && PrivilegeConstants.JCR_WRITE.equals(next2.getName())) ||
                            (PrivilegeConstants.JCR_READ.equals(next2.getName()) && PrivilegeConstants.JCR_WRITE.equals(next.getName())) ) {
                        //read/write privileges
                        return getResourceBundle(locale).getString("privilegeset.readwrite");
                    }
                }

                //some other set of privileges
                return getResourceBundle(locale).getString("privilegeset.custom");
            }
        }
    }

    /**
     * Returns the mapping of declared access rights that have been set for the resource at
     * the given path. 
     * 
     * @param node the node to get the access rights for
     * @return map of access rights.  Key is the user/group principal, value contains the granted/denied privileges
     * @throws RepositoryException if any errors reading the information
     */
    public Map<Principal, AccessRights> getDeclaredAccessRights(Node node) throws RepositoryException {
        return getDeclaredAccessRights(node.getSession(), node.getPath());
    }

    /**
     * Returns the mapping of declared access rights that have been set for the resource at
     * the given path.
     *
     * @param session the current user session.
     * @param absPath the path of the resource to get the access rights for
     * @return map of access rights.  Key is the user/group principal, value contains the granted/denied privileges
     * @throws RepositoryException if any errors reading the information
     */
    public Map<Principal, AccessRights> getDeclaredAccessRights(Session session, String absPath) throws RepositoryException {
        JsonObject aclJson = useGetAcl(json -> {
            try {
                return json.getAcl(session, absPath);
            } catch (RepositoryException e) {
                logger.warn("Failed to load Acl", e);
            }
            return null;
        });

        Map<Principal, AccessRights> map;
        if (aclJson == null) {
            map = Collections.emptyMap();
        } else {
            map = toMap(session, aclJson);
        }
        return map;
    }

    /**
     * Convert the JSON acl to a map of Principal to AccessRights
     * @param session the jcr session
     * @param aclJson the acl JSON object
     * @return map of Principal to AccessRights
     */
    protected Map<Principal, AccessRights> toMap(Session session, JsonObject aclJson)
            throws RepositoryException {
        Map<Principal, AccessRights> map;
        AccessControlManager acm = session.getAccessControlManager();
        PrincipalManager principalManager = AccessControlUtil.getPrincipalManager(session);
        Function<? super JsonValue, ? extends Principal> keyMapper = val -> {
            String principalId = ((JsonObject)val).getString(JsonConvert.KEY_PRINCIPAL);
            return principalManager.getPrincipal(principalId);
        };
        Function<? super JsonValue, ? extends AccessRights> valueMapper = val -> {
            AccessRights rights = new AccessRights();
            JsonObject privilegesObj = ((JsonObject)val).getJsonObject(JsonConvert.KEY_PRIVILEGES);
            if (privilegesObj != null) {
                privilegesObj.entrySet().stream()
                    .forEach(entry -> {
                        Privilege privilege = null;
                        try {
                            privilege = acm.privilegeFromName(entry.getKey());
                        } catch (RepositoryException e) {
                            logger.warn("Failed to resolve privilege", e);
                        }
                        if (privilege != null) {
                            JsonValue value = entry.getValue();
                            if (value instanceof JsonObject) {
                                JsonObject privilegeObj = (JsonObject)value;
                                if (privilegeObj.containsKey(JsonConvert.KEY_ALLOW)) {
                                    rights.granted.add(privilege);
                                }
                                if (privilegeObj.containsKey(JsonConvert.KEY_DENY)) {
                                    rights.denied.add(privilege);
                                }
                            }
                        }
                    });
            }
            return rights;
        };
        map = aclJson.values().stream()
                .collect(Collectors.toMap(keyMapper, valueMapper));
        return map;
    }

    /**
     * Returns the declared access rights for the specified Node for the given
     * principalId.
     *
     * @param node the JCR node to retrieve the access rights for
     * @param principalId the principalId to get the access rights for
     * @return access rights for the specified principal
     * @throws RepositoryException if any errors reading the information
     */
    public AccessRights getDeclaredAccessRightsForPrincipal(Node node, String principalId) throws RepositoryException {
        return getDeclaredAccessRightsForPrincipal(node.getSession(), node.getPath(), principalId);
    }

    /**
     * Returns the declared access rights for the resource at the specified path for the given
     * principalId.
     *
     * @param session the current JCR session
     * @param absPath the path of the resource to retrieve the rights for
     * @param principalId the principalId to get the access rights for
     * @return access rights for the specified principal
     * @throws RepositoryException if any errors reading the information
     */
    public AccessRights getDeclaredAccessRightsForPrincipal(Session session, String absPath, String principalId) throws RepositoryException {
        Map<Principal, AccessRights> declaredAccessRights = getDeclaredAccessRights(session, absPath);
        PrincipalManager principalManager = AccessControlUtil.getPrincipalManager(session);
        Principal principal = principalManager.getPrincipal(principalId);
        return declaredAccessRights.get(principal);
    }

    /**
     * Returns the restrictions for the specified path.
     *
     * @param node the node to inspect
     * @param principalId the principalId to get the access rights for
     * @return map of restrictions (key is restriction name, value is Value or Value[])
     * @throws RepositoryException if any errors reading the information
     * @deprecated don't use this as it assumes that all the privileges have the same restrictions which may not be true
     */
    @Deprecated
    public Map<String, Object> getDeclaredRestrictionsForPrincipal(Node node, String principalId) throws RepositoryException {
        return getDeclaredRestrictionsForPrincipal(node.getSession(), node.getPath(), principalId);
    }

    /**
     * Returns the restrictions for the specified path.
     *
     * @param session the session for the current user
     * @param absPath the path to get the privileges for
     * @param principalId the principalId to get the access rights for
     * @return map of restrictions (key is restriction name, value is Value or Value[])
     * @throws RepositoryException if any errors reading the information
     * @deprecated don't use this as it assumes that all the privileges have the same restrictions which may not be true
     */
    @Deprecated
    public Map<String, Object> getDeclaredRestrictionsForPrincipal(Session session, String absPath, String principalId) throws RepositoryException {
        JsonObject aclJson = useGetAcl(json -> {
            try {
                return json.getAcl(session, absPath);
            } catch (RepositoryException e) {
                logger.warn("Failed to load Acl", e);
            }
            return null;
        });

        Map<String, Object> map;
        if (aclJson == null) {
            map = Collections.emptyMap();
        } else {
            Map<String, RestrictionDefinition> srMap = new HashMap<>();
            useRestrictionProvider(restrictionProvider -> {
                Set<RestrictionDefinition> supportedRestrictions = restrictionProvider.getSupportedRestrictions(absPath);
                for (RestrictionDefinition restrictionDefinition : supportedRestrictions) {
                    srMap.put(restrictionDefinition.getName(), restrictionDefinition);
                }
                return null;
            });

            ValueFactory valueFactory = session.getValueFactory();
            map = new HashMap<>();
            aclJson.values().stream()
                    .filter(val -> val instanceof JsonObject && ((JsonObject)val).getString(JsonConvert.KEY_PRINCIPAL).equals(principalId))
                    .forEach(item -> {
                        JsonObject privilegesObj = ((JsonObject)item).getJsonObject(JsonConvert.KEY_PRIVILEGES);
                        if (privilegesObj != null) {
                            privilegesObj.values()
                                .forEach(privItem -> {
                                    if (privItem instanceof JsonObject) {
                                        JsonObject privilegeObj = (JsonObject)privItem;
                                        JsonValue jsonValue = privilegeObj.get(JsonConvert.KEY_ALLOW);
                                        if (jsonValue instanceof JsonObject) {
                                            JsonObject restriction = (JsonObject)jsonValue;
                                            restriction.entrySet().stream()
                                                .forEach(restrictionItem -> {
                                                    String restrictionName = restrictionItem.getKey();
                                                    int type = srMap.get(restrictionName).getRequiredType().tag();
                                                    JsonValue value = restrictionItem.getValue();
                                                    if (ValueType.ARRAY.equals(value.getValueType())) {
                                                        JsonArray jsonArray = ((JsonArray)value);
                                                        Value [] restrictionValues = new Value[jsonArray.size()];
                                                        for (int i=0; i < jsonArray.size(); i++) {
                                                            try {
                                                                restrictionValues[i] = valueFactory.createValue(jsonArray.getString(i), type);
                                                            } catch (ValueFormatException e) {
                                                                logger.warn("Failed to create restriction value", e);
                                                            }
                                                        }
                                                        map.put(restrictionName, restrictionValues);
                                                    } else if (value instanceof JsonString){
                                                        try {
                                                            Value restrictionValue = valueFactory.createValue(((JsonString)value).getString(), type);
                                                            map.put(restrictionName, restrictionValue);
                                                        } catch (ValueFormatException e) {
                                                            logger.warn("Failed to create restriction value", e);
                                                        }
                                                    }
                                                });
                                        }
                                    }
                                });
                        }
                    });
        }
        return map;
    }

    /**
     * Returns the mapping of effective access rights that have been set for the resource at
     * the given path.
     *
     * @param node the node to get the access rights for
     * @return map of access rights.  Key is the user/group principal, value contains the granted/denied privileges
     * @throws RepositoryException if any errors reading the information
     */
    public Map<Principal, AccessRights> getEffectiveAccessRights(Node node) throws RepositoryException {
        return getEffectiveAccessRights(node.getSession(), node.getPath());
    }

    /**
     * Returns the mapping of effective access rights that have been set for the resource at
     * the given path.
     *
     * @param session the current user session.
     * @param absPath the path of the resource to get the access rights for
     * @return map of access rights.  Key is the user/group principal, value contains the granted/denied privileges
     * @throws RepositoryException if any errors reading the information
     */
    public Map<Principal, AccessRights> getEffectiveAccessRights(Session session, String absPath) throws RepositoryException {
        JsonObject aclJson = useGetEffectiveAcl(json -> {
            try {
                return json.getEffectiveAcl(session, absPath);
            } catch (RepositoryException e) {
                logger.warn("Failed to load EffectiveAcl", e);
            }
            return null;
        });

        Map<Principal, AccessRights> map;
        if (aclJson == null) {
            map = Collections.emptyMap();
        } else {
            map = toMap(session, aclJson);
        }
        return map;
    }

    /**
     * Returns the effective access rights for the specified Node for the given
     * principalId.
     * 
     * @param node the JCR node to retrieve the access rights for
     * @param principalId the principalId to get the access rights for
     * @return access rights for the specified principal
     * @throws RepositoryException if any errors reading the information
     */
    public AccessRights getEffectiveAccessRightsForPrincipal(Node node, String principalId) throws RepositoryException {
        return getEffectiveAccessRightsForPrincipal(node.getSession(), node.getPath(), principalId);
    }

    /**
     * Returns the effective access rights for the resource at the specified path for the given
     * principalId.
     *
     * @param session the current JCR session
     * @param absPath the path of the resource to retrieve the rights for
     * @param principalId the principalId to get the access rights for
     * @return access rights for the specified principal
     * @throws RepositoryException if any errors reading the information
     */
    public AccessRights getEffectiveAccessRightsForPrincipal(Session session, String absPath, String principalId) throws RepositoryException {
        Map<Principal, AccessRights> effectiveAccessRights = getEffectiveAccessRights(session, absPath);
        PrincipalManager principalManager = AccessControlUtil.getPrincipalManager(session);
        Principal principal = principalManager.getPrincipal(principalId);
        return effectiveAccessRights.get(principal);
    }

    /**
     * Checks whether the current user has been granted privileges
     * to add children to the specified node.
     *
     * @param node the node to check
     * @return true if the current user has the privileges, false otherwise
     */
    public boolean canAddChildren(Node node) {
        try {
            return canAddChildren(node.getSession(), node.getPath());
        } catch (RepositoryException e) {
            return false;
        }
    }

    /**
     * Checks whether the current user has been granted privileges
     * to add children to the specified path.
     *
     * @param session the JCR session of the current user
     * @param absPath the path of the resource to check
     * @return true if the current user has the privileges, false otherwise
     */
    public boolean canAddChildren(Session session, String absPath) {
        try {
            AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);
            return accessControlManager.hasPrivileges(absPath, new Privilege[] {
                            accessControlManager.privilegeFromName(Privilege.JCR_ADD_CHILD_NODES)
                        });
        } catch (RepositoryException e) {
            return false;
        }
    }

    /**
     * Checks whether the current user has been granted privileges
     * to delete children to the specified node.
     *
     * @param node the node to check
     * @return true if the current user has the privileges, false otherwise
     */
    public boolean canDeleteChildren(Node node) {
        try {
            return canDeleteChildren(node.getSession(), node.getPath());
        } catch (RepositoryException e) {
            return false;
        }
    }

    /**
     * Checks whether the current user has been granted privileges
     * to delete children of the specified path.
     *
     * @param session the JCR session of the current user
     * @param absPath the path of the resource to check
     * @return true if the current user has the privileges, false otherwise
     */
    public boolean canDeleteChildren(Session session, String absPath) {
        try {
            AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);
            
            return accessControlManager.hasPrivileges(absPath, new Privilege[] {
                            accessControlManager.privilegeFromName(Privilege.JCR_REMOVE_CHILD_NODES)
                        });
        } catch (RepositoryException e) {
            return false;
        }
    }

    /**
     * Checks whether the current user has been granted privileges
     * to delete the specified node.
     *
     * @param node the node to check
     * @return true if the current user has the privileges, false otherwise
     */
    public boolean canDelete(Node node) {
        try {
            return canDelete(node.getSession(), node.getPath());
        } catch (RepositoryException e) {
            return false;
        }
    }

    /**
     * Checks whether the current user has been granted privileges
     * to delete the specified path.
     *
     * @param session the JCR session of the current user
     * @param absPath the path of the resource to check
     * @return true if the current user has the privileges, false otherwise
     */
    public boolean canDelete(Session session, String absPath) {
        try {
            AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);

            String parentPath;
            int lastSlash = absPath.lastIndexOf('/');
            if (lastSlash == 0) {
                //the parent is the root folder.
                parentPath = "/";
            } else {
                //strip the last segment
                parentPath = absPath.substring(0, lastSlash);
            }
            return accessControlManager.hasPrivileges(absPath, new Privilege[] {
                            accessControlManager.privilegeFromName(Privilege.JCR_REMOVE_NODE)
                        }) && canDeleteChildren(session, parentPath);
        } catch (RepositoryException e) {
            return false;
        }
    }

    /**
     * Checks whether the current user has been granted privileges
     * to modify properties of the specified node.
     *
     * @param node the node to check
     * @return true if the current user has the privileges, false otherwise
     */
    public boolean canModifyProperties(Node node) {
        try {
            return canModifyProperties(node.getSession(), node.getPath());
        } catch (RepositoryException e) {
            return false;
        }
    }

    /**
     * Checks whether the current user has been granted privileges
     * to modify properties of the specified path.
     *
     * @param session the JCR session of the current user
     * @param absPath the path of the resource to check
     * @return true if the current user has the privileges, false otherwise
     */
    public boolean canModifyProperties(Session session, String absPath) {
        try {
            AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);
            return accessControlManager.hasPrivileges(absPath, new Privilege[] {
                            accessControlManager.privilegeFromName(Privilege.JCR_MODIFY_PROPERTIES)
                        });
        } catch (RepositoryException e) {
            return false;
        }
    }

    /**
     * Checks whether the current user has been granted privileges
     * to read the access control of the specified node.
     *
     * @param node the node to check
     * @return true if the current user has the privileges, false otherwise
     */
    public boolean canReadAccessControl(Node node) {
        try {
            return canReadAccessControl(node.getSession(), node.getPath());
        } catch (RepositoryException e) {
            return false;
        }
    }

    /**
     * Checks whether the current user has been granted privileges
     * to read the access control of the specified path.
     *
     * @param session the JCR session of the current user
     * @param absPath the path of the resource to check
     * @return true if the current user has the privileges, false otherwise
     */
    public boolean canReadAccessControl(Session session, String absPath) {
        try {
            AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);
            return accessControlManager.hasPrivileges(absPath, new Privilege[] {
                            accessControlManager.privilegeFromName(Privilege.JCR_READ_ACCESS_CONTROL)
                        });
        } catch (RepositoryException e) {
            return false;
        }
    }

    /**
     * Checks whether the current user has been granted privileges
     * to modify the access control of the specified node.
     *
     * @param node the node to check
     * @return true if the current user has the privileges, false otherwise
     */
    public boolean canModifyAccessControl(Node node) {
        try {
            return canModifyAccessControl(node.getSession(), node.getPath());
        } catch (RepositoryException e) {
            return false;
        }
    }

    /**
     * Checks whether the current user has been granted privileges
     * to modify the access control of the specified path.
     *
     * @param session the JCR session of the current user
     * @param absPath the path of the resource to check
     * @return true if the current user has the privileges, false otherwise
     */
    public boolean canModifyAccessControl(Session session, String absPath) {
        try {
            AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);
            return accessControlManager.hasPrivileges(absPath, new Privilege[] {
                            accessControlManager.privilegeFromName(Privilege.JCR_MODIFY_ACCESS_CONTROL)
                        });
        } catch (RepositoryException e) {
            return false;
        }
    }

    private static <T> T useGetAcl(Function<GetAcl, T> fn) {
        T value = null;
        Bundle bundle = FrameworkUtil.getBundle(GetAcl.class);
        if (bundle != null) {
            BundleContext bundleContext = bundle.getBundleContext();
            if (bundleContext != null) {
                ServiceReference<GetAcl> serviceReference = bundleContext.getServiceReference(GetAcl.class);
                if (serviceReference != null) {
                    GetAcl service = null;
                    try {
                        service = bundleContext.getService(serviceReference);
                        if (service != null) {
                            value = fn.apply(service);
                        }
                    } finally {
                        if (service != null) {
                            bundleContext.ungetService(serviceReference);
                        }
                    }
                }
            }
        }
        return value;
    }

    private static <T> T useGetEffectiveAcl(Function<GetEffectiveAcl, T> fn) {
        T value = null;
        Bundle bundle = FrameworkUtil.getBundle(GetAcl.class);
        if (bundle != null) {
            BundleContext bundleContext = bundle.getBundleContext();
            if (bundleContext != null) {
                ServiceReference<GetEffectiveAcl> serviceReference = bundleContext.getServiceReference(GetEffectiveAcl.class);
                if (serviceReference != null) {
                    GetEffectiveAcl service = null;
                    try {
                        service = bundleContext.getService(serviceReference);
                        if (service != null) {
                            value = fn.apply(service);
                        }
                    } finally {
                        if (service != null) {
                            bundleContext.ungetService(serviceReference);
                        }
                    }
                }
            }
        }
        return value;
    }

    private static <T> T useRestrictionProvider(Function<RestrictionProvider, T> fn) {
        T value = null;
        Bundle bundle = FrameworkUtil.getBundle(GetAcl.class);
        if (bundle != null) {
            BundleContext bundleContext = bundle.getBundleContext();
            if (bundleContext != null) {
                ServiceReference<RestrictionProvider> serviceReference = bundleContext.getServiceReference(RestrictionProvider.class);
                if (serviceReference != null) {
                    RestrictionProvider service = null;
                    try {
                        service = bundleContext.getService(serviceReference);
                        if (service != null) {
                            value = fn.apply(service);
                        }
                    } finally {
                        if (service != null) {
                            bundleContext.ungetService(serviceReference);
                        }
                    }
                }
            }
        }
        return value;
    }

}
