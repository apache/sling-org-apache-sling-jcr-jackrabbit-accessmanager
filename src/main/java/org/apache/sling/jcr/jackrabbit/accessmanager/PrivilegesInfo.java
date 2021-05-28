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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;

import javax.jcr.Node;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.Value;
import javax.jcr.ValueFormatException;
import javax.jcr.security.AccessControlEntry;
import javax.jcr.security.AccessControlList;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.AccessControlPolicy;
import javax.jcr.security.Privilege;

import org.apache.jackrabbit.api.security.JackrabbitAccessControlEntry;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.sling.jcr.base.util.AccessControlUtil;

/**
 * Helper class to assist in the usage of access control from scripts.
 */
public class PrivilegesInfo {

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
        AccessControlEntry[] entries = getDeclaredAccessControlEntries(session, absPath);
        return mergePrivilegesFromEntries(entries);
    }

    private AccessControlEntry[] getDeclaredAccessControlEntries(Session session, String absPath) throws RepositoryException {
        AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);
        AccessControlPolicy[] policies = accessControlManager.getPolicies(absPath);

        List<AccessControlEntry> allEntries = new ArrayList<>();
        for (AccessControlPolicy accessControlPolicy : policies) {
            if (accessControlPolicy instanceof AccessControlList) {
                AccessControlEntry[] accessControlEntries = ((AccessControlList)accessControlPolicy).getAccessControlEntries();
                allEntries.addAll(Arrays.asList(accessControlEntries));
            }
        }
        return allEntries.toArray(new AccessControlEntry[allEntries.size()]);
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
        AccessRights rights = new AccessRights();
        if (principalId != null && principalId.length() > 0) {
            AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);
            AccessControlPolicy[] policies = accessControlManager.getPolicies(absPath);
            for (AccessControlPolicy accessControlPolicy : policies) {
                if (accessControlPolicy instanceof AccessControlList) {
                    AccessControlEntry[] accessControlEntries = ((AccessControlList)accessControlPolicy).getAccessControlEntries();
                    for (AccessControlEntry ace : accessControlEntries) {
                        if (principalId.equals(ace.getPrincipal().getName())) {
                            boolean isAllow = AccessControlUtil.isAllow(ace);
                            if (isAllow) {
                                rights.getGranted().addAll(Arrays.asList(ace.getPrivileges()));
                            } else {
                                rights.getDenied().addAll(Arrays.asList(ace.getPrivileges()));
                            }
                        }
                    }
                }
            }
        }

        return rights;
    }

    /**
     * Returns the restrictions for the specified path.
     *
     * @param node the node to inspect
     * @param principalId the principalId to get the access rights for
     * @return map of restrictions (key is restriction name, value is Value or Value[])
     * @throws RepositoryException if any errors reading the information
     */
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
     */
    public Map<String, Object> getDeclaredRestrictionsForPrincipal(Session session, String absPath, String principalId) throws RepositoryException {
        Map<String, Object> restrictions = new LinkedHashMap<>();
        AccessControlEntry[] entries = getDeclaredAccessControlEntries(session, absPath);
        if (entries != null) {
            for (AccessControlEntry ace : entries) {
                if (principalId.equals(ace.getPrincipal().getName()) &&
                        ace instanceof JackrabbitAccessControlEntry) {
                    JackrabbitAccessControlEntry jace = (JackrabbitAccessControlEntry)ace;
                    String[] restrictionNames = jace.getRestrictionNames();
                    if (restrictionNames != null) {
                        for (String name : restrictionNames) {
                            try {
                                Value value = jace.getRestriction(name);
                                if (value != null) {
                                    restrictions.put(name, value);
                                }
                            } catch (ValueFormatException vfe) {
                                //try multi-value restriction
                                Value[] values = jace.getRestrictions(name);
                                if (values != null && values.length > 0) {
                                    restrictions.put(name,  values);
                                }
                            }
                        }
                    }
                }
            }
        }
        return restrictions;
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
        AccessControlEntry[] entries = getEffectiveAccessControlEntries(session, absPath);
        return mergePrivilegesFromEntries(entries);
    }

    /**
     * Loop through each of the entries to merge the granted and denied privileges into
     * the map
     *
     * @param entries the entries to process
     * @throws RepositoryException if any errors reading the information
     */
    private Map<Principal, AccessRights> mergePrivilegesFromEntries(AccessControlEntry[] entries)
            throws RepositoryException {
        Map<Principal, AccessRights> accessMap = new LinkedHashMap<>();
        if (entries != null) {
            for (AccessControlEntry ace : entries) {
                Principal principal = ace.getPrincipal();
                AccessRights accessPrivileges = accessMap.computeIfAbsent(principal, k -> new AccessRights());
                boolean allow = AccessControlUtil.isAllow(ace);
                if (allow) {
                    accessPrivileges.getGranted().addAll(Arrays.asList(ace.getPrivileges()));
                } else {
                    accessPrivileges.getDenied().addAll(Arrays.asList(ace.getPrivileges()));
                }
            }
        }
        return accessMap;
    }

    private AccessControlEntry[] getEffectiveAccessControlEntries(Session session, String absPath) throws RepositoryException {
        AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);
        AccessControlPolicy[] policies = accessControlManager.getEffectivePolicies(absPath);

        List<AccessControlEntry> allEntries = new ArrayList<>();
        for (AccessControlPolicy accessControlPolicy : policies) {
            if (accessControlPolicy instanceof AccessControlList) {
                AccessControlEntry[] accessControlEntries = ((AccessControlList)accessControlPolicy).getAccessControlEntries();
                allEntries.addAll(Arrays.asList(accessControlEntries));
            }
        }
        return allEntries.toArray(new AccessControlEntry[allEntries.size()]);
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
        AccessRights rights = new AccessRights();
        if (principalId != null && principalId.length() > 0) {
            AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);
            AccessControlPolicy[] policies = accessControlManager.getEffectivePolicies(absPath);
            for (AccessControlPolicy accessControlPolicy : policies) {
                if (accessControlPolicy instanceof AccessControlList) {
                    AccessControlEntry[] accessControlEntries = ((AccessControlList)accessControlPolicy).getAccessControlEntries();
                    for (AccessControlEntry ace : accessControlEntries) {
                        if (principalId.equals(ace.getPrincipal().getName())) {
                            boolean isAllow = AccessControlUtil.isAllow(ace);
                            if (isAllow) {
                                rights.getGranted().addAll(Arrays.asList(ace.getPrivileges()));
                            } else {
                                rights.getDenied().addAll(Arrays.asList(ace.getPrivileges()));
                            }
                        }
                    }
                }
            }
        }

        return rights;
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

}
