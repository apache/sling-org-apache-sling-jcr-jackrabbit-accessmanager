/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sling.jcr.jackrabbit.accessmanager.impl;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.Workspace;
import javax.jcr.security.Privilege;

import org.apache.jackrabbit.api.JackrabbitWorkspace;
import org.apache.jackrabbit.api.security.authorization.PrivilegeManager;
import org.apache.sling.jcr.jackrabbit.accessmanager.LocalPrivilege;
import org.apache.sling.jcr.jackrabbit.accessmanager.LocalRestriction;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * Contains utility methods related to handling privileges 
 */
public final class PrivilegesHelper {

    private PrivilegesHelper() {

    }

    /**
     * If the privilege is contained in multiple aggregate privileges, then
     * calculate the instance with the greatest depth.
     */
    private static void toLongestDepth(int parentDepth, Privilege parentPrivilege, Map<Privilege, Integer> privilegeToLongestDepth) {
        Privilege[] declaredAggregatePrivileges = parentPrivilege.getDeclaredAggregatePrivileges();
        for (Privilege privilege : declaredAggregatePrivileges) {
            Integer oldValue = privilegeToLongestDepth.get(privilege);
            int candidateDepth = parentDepth + 1;
            if (oldValue == null || oldValue.intValue() < candidateDepth) {
                privilegeToLongestDepth.put(privilege, candidateDepth);

                // continue drilling down to the leaf privileges
                toLongestDepth(candidateDepth, privilege, privilegeToLongestDepth);
            }
        }
    }

    /**
     * Calculate the longest path for each of the possible privileges
     * 
     * @param jcrSession the current users JCR session
     * @return map where the key is the privilege and the value is the longest path
     */
    public static Map<Privilege, Integer> buildPrivilegeLongestDepthMap(Privilege jcrAll) {
        Map<Privilege, Integer> privilegeToLongestPath = new HashMap<>();
        privilegeToLongestPath.put(jcrAll, 1);
        toLongestDepth(1, jcrAll, privilegeToLongestPath);
        return privilegeToLongestPath;
    }

    /**
     * Populates a local allow privilege in the privilegeToLocalPrivilegesMap
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param privilege the privilege to allow
     * @param isAllow true or false to set the allow value of the LocalPrivilege
     * @param restrictions if isAllow is true, the set of restrictions
     * @return the LocalPrivileges that was populated
     */
    public static LocalPrivilege localAllowPriv(Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap, 
            Privilege privilege, boolean isAllow, Set<LocalRestriction> restrictions) {
        LocalPrivilege localPrivilege = privilegeToLocalPrivilegesMap.computeIfAbsent(privilege, LocalPrivilege::new);
        localPrivilege.setAllow(isAllow);
        if (isAllow) {
            localPrivilege.setAllowRestrictions(restrictions);
            if (localPrivilege.isDeny() && localPrivilege.sameAllowAndDenyRestrictions()) {
                // same restrictions to we can unset the other one
                localPrivilege.setDeny(false);
                localPrivilege.setDenyRestrictions(Collections.emptySet());
            }
        } else {
            localPrivilege.setAllowRestrictions(Collections.emptySet());
        }
        return localPrivilege;
    }

    /**
     * Populates a local deny privilege in the privilegeToLocalPrivilegesMap
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param privilege the privilege to deny
     * @param isDeny true or false to set the deny value of the LocalPrivilege
     * @param restrictions if isDeny is true, the set of restrictions
     * @return the LocalPrivileges that was populated
     */
    public static LocalPrivilege localDenyPriv(Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap, 
            Privilege privilege, boolean isDeny, Set<LocalRestriction> restrictions) {
        LocalPrivilege localPrivilege = privilegeToLocalPrivilegesMap.computeIfAbsent(privilege, LocalPrivilege::new);
        localPrivilege.setDeny(isDeny);
        if (isDeny) {
            localPrivilege.setDenyRestrictions(restrictions);
            if (localPrivilege.sameAllowAndDenyRestrictions()) {
                // same restrictions to we can unset the other one
                localPrivilege.setAllow(false);
                localPrivilege.setAllowRestrictions(Collections.emptySet());
            }
        } else {
            localPrivilege.setDenyRestrictions(Collections.emptySet());
        }
        return localPrivilege;
    }

    /**
     * Populates each of the local allow privilege in the privilegeToLocalPrivilegesMap.  If the supplied
     * privilege is an aggregate then the data is populated for each of non-aggregate privileges contained in
     * the aggregate privilege.  Otherwise, the data is populated for the privilege itself.
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param p the privilege to update
     * @param isAllow true or false to set the allow value of the LocalPrivilege
     * @param restrictions if isAllow is true, the set of restrictions
     */
    private static void expandAllowPrivWithoutAggregates(Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap,
            Privilege p, boolean isAllow, Set<LocalRestriction> restrictions) throws RepositoryException {
        if (p.isAggregate()) {
            Privilege[] aggregatePrivileges = p.getDeclaredAggregatePrivileges();
            for (Privilege aggregatePrivilege : aggregatePrivileges) {
                if (aggregatePrivilege.isAggregate()) {
                    expandAllowPrivWithoutAggregates(privilegeToLocalPrivilegesMap, aggregatePrivilege, isAllow, restrictions);
                } else {
                    localAllowPriv(privilegeToLocalPrivilegesMap, aggregatePrivilege, isAllow, restrictions);
                }
            }
        } else {
            localAllowPriv(privilegeToLocalPrivilegesMap, p, isAllow, restrictions);
        }
    }

    /**
     * Populates each of the local deny privilege in the privilegeToLocalPrivilegesMap.  If the supplied
     * privilege is an aggregate then the data is populated for each of non-aggregate privileges contained in
     * the aggregate privilege.  Otherwise, the data is populated for the privilege itself.
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param p the privilege to update
     * @param isDeny true or false to set the allow value of the LocalPrivilege
     * @param restrictions if isDeny is true, the set of restrictions
     */
    private static void expandDenyPrivWithoutAggregates(Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap,
            Privilege p, boolean isDeny, Set<LocalRestriction> restrictions) throws RepositoryException {
        if (p.isAggregate()) {
            Privilege[] aggregatePrivileges = p.getDeclaredAggregatePrivileges();
            for (Privilege aggregatePrivilege : aggregatePrivileges) {
                if (aggregatePrivilege.isAggregate()) {
                    expandDenyPrivWithoutAggregates(privilegeToLocalPrivilegesMap, aggregatePrivilege, isDeny, restrictions);
                } else {
                    localDenyPriv(privilegeToLocalPrivilegesMap, aggregatePrivilege, isDeny, restrictions);
                }
            }
        } else {
            localDenyPriv(privilegeToLocalPrivilegesMap, p, isDeny, restrictions);
        }
    }

    /**
     * Populates each of the allow privilege in the privilegeToLocalPrivilegesMap.
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param restrictions the set of restrictions (possibly empty)
     * @param privileges the privilege to update
     */
    public static void allow(@NotNull Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap,
            @NotNull Set<LocalRestriction> restrictions, @NotNull Collection<Privilege> privileges) throws RepositoryException {
        for (Privilege privilege : privileges) {
            expandAllowPrivWithoutAggregates(privilegeToLocalPrivilegesMap, privilege, true, restrictions);
        }
    }

    /**
     * Unset each of the allow privilege in the privilegeToLocalPrivilegesMap.
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param privileges the privilege to update
     */
    public static void unallow(@NotNull Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap,
            @NotNull Collection<Privilege> privileges) throws RepositoryException {
        for (Privilege privilege : privileges) {
            expandAllowPrivWithoutAggregates(privilegeToLocalPrivilegesMap, privilege, false, Collections.emptySet());
        }
    }

    /**
     * Populates each of the deny privilege in the privilegeToLocalPrivilegesMap.
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param restrictions the set of restrictions (possibly empty)
     * @param privileges the privilege to update
     */
    public static void deny(@NotNull Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap,
            @NotNull Set<LocalRestriction> restrictions, @NotNull Collection<Privilege> privileges) throws RepositoryException {
        for (Privilege privilege : privileges) {
            expandDenyPrivWithoutAggregates(privilegeToLocalPrivilegesMap, privilege, true, restrictions);
        }
    }

    /**
     * Unset each of the deny privilege in the privilegeToLocalPrivilegesMap.
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param privileges the privilege to update
     */
    public static void undeny(@NotNull Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap,
            @NotNull Collection<Privilege> privileges) throws RepositoryException {
        for (Privilege privilege : privileges) {
            expandDenyPrivWithoutAggregates(privilegeToLocalPrivilegesMap, privilege, false, Collections.emptySet());
        }
    }

    /**
     * Unset each of the allow and deny privilege in the privilegeToLocalPrivilegesMap.
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param privileges the privilege to update
     */
    public static void none(@NotNull Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap, @NotNull Collection<Privilege> privileges) throws RepositoryException {
        for (Privilege privilege : privileges) {
            expandAllowPrivWithoutAggregates(privilegeToLocalPrivilegesMap, privilege, false, Collections.emptySet());
            expandDenyPrivWithoutAggregates(privilegeToLocalPrivilegesMap, privilege, false, Collections.emptySet());
        }
    }

    /**
     * Remove the specified restrictions from the LocalPrivilege
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param privileges the privilege to update
     * @param forAllow true to remove allow restrictions
     * @param forDeny true to remove deny restrictions
     * @param restrictionNames the set of restriction names to remove
     * @return the local privilege that was populated
     */
    private static LocalPrivilege localPrivRemoveRestrictions(@NotNull Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap, 
            @NotNull Privilege privilege, boolean forAllow, boolean forDeny, @NotNull Collection<String> restrictionNames) {
        LocalPrivilege localPrivilege = privilegeToLocalPrivilegesMap.computeIfAbsent(privilege, LocalPrivilege::new);
        // make sure allow/deny already exists
        forAllow &= localPrivilege.isAllow();
        forDeny &= localPrivilege.isDeny();
        if (forAllow) {
            localPrivilege.unsetAllowRestrictions(restrictionNames);
        }
        if (forDeny) {
            localPrivilege.unsetDenyRestrictions(restrictionNames);
        }

        if (localPrivilege.sameAllowAndDenyRestrictions()) {
            // same restrictions so we can unset one of them
            if (forAllow) {
                localPrivilege.setDeny(false);
                localPrivilege.clearDenyRestrictions();
            } else if (forDeny) {
                localPrivilege.setAllow(false);
                localPrivilege.clearAllowRestrictions();
            }
        }

        return localPrivilege;
    }

    /**
     * Remove the specified restrictions from each of the local privilege in the privilegeToLocalPrivilegesMap.
     * If the supplied privilege is an aggregate then the data is populated for each of non-aggregate privileges contained in
     * the aggregate privilege.  Otherwise, the data is populated for the privilege itself.
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param privileges the privilege to update
     * @param forAllow true to remove allow restrictions
     * @param forDeny true to remove deny restrictions
     * @param restrictionNames the set of restriction names to remove
     * @return the local privilege that was populated
     */
    private static void removeRestrictionsWithoutAggregates(@NotNull Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap,
            @NotNull Privilege p, boolean forAllow, boolean forDeny, @NotNull Collection<String> restrictionNames) throws RepositoryException {
        if (p.isAggregate()) {
            Privilege[] aggregatePrivileges = p.getDeclaredAggregatePrivileges();
            for (Privilege aggregatePrivilege : aggregatePrivileges) {
                if (aggregatePrivilege.isAggregate()) {
                    removeRestrictionsWithoutAggregates(privilegeToLocalPrivilegesMap, aggregatePrivilege, forAllow, forDeny, restrictionNames);
                } else {
                    localPrivRemoveRestrictions(privilegeToLocalPrivilegesMap, aggregatePrivilege, forAllow, forDeny, restrictionNames);
                }
            }
        } else {
            localPrivRemoveRestrictions(privilegeToLocalPrivilegesMap, p, forAllow, forDeny, restrictionNames);
        }
    }

    /**
     * Add the specified restriction to the LocalPrivilege
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param privileges the privilege to update
     * @param forAllow true to remove allow restrictions
     * @param forDeny true to remove deny restrictions
     * @param restriction the restriction to add
     * @param requireAllowOrDenyAlreadySet if true, only do work if the allow/deny state is already set to true
     * @return the local privilege that was populated
     */
    private static LocalPrivilege localPrivAddRestriction(@NotNull Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap,
            @NotNull Privilege privilege, boolean forAllow, boolean forDeny, @NotNull LocalRestriction restriction,
            boolean requireAllowOrDenyAlreadySet) {
        LocalPrivilege localPrivilege = privilegeToLocalPrivilegesMap.computeIfAbsent(privilege, LocalPrivilege::new);
        if (forDeny) {
            if (requireAllowOrDenyAlreadySet && !localPrivilege.isDeny()) {
                //skip it
            } else {
                localPrivilege.setDeny(true);
                localPrivilege.unsetDenyRestrictions(Collections.singleton(restriction.getName()));
                localPrivilege.setDenyRestrictions(Collections.singleton(restriction));
            }
        }
        if (forAllow) {
            if (requireAllowOrDenyAlreadySet && !localPrivilege.isAllow()) {
                //skip it
            } else {
                localPrivilege.setAllow(true);
                localPrivilege.unsetAllowRestrictions(Collections.singleton(restriction.getName()));
                localPrivilege.setAllowRestrictions(Collections.singleton(restriction));
            }
        }

        if (localPrivilege.sameAllowAndDenyRestrictions()) {
            // same restrictions so we can unset one of them
            if (forAllow) {
                localPrivilege.setDeny(false);
                localPrivilege.setDenyRestrictions(Collections.emptySet());
            } else if (forDeny) {
                localPrivilege.setAllow(false);
                localPrivilege.setAllowRestrictions(Collections.emptySet());
            }
        }

        return localPrivilege;
    }

    /**
     * Add the specified restrictions to each of the local privilege in the privilegeToLocalPrivilegesMap.
     * If the supplied privilege is an aggregate then the data is populated for each of non-aggregate privileges contained in
     * the aggregate privilege.  Otherwise, the data is populated for the privilege itself.
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param privileges the privilege to update
     * @param forAllow true to remove allow restrictions
     * @param forDeny true to remove deny restrictions
     * @param restrictionNames the set of restriction names to remove
     * @return the local privilege that was populated
     */
    private static void addRestrictionWithoutAggregates(Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap,
            Privilege p, boolean forAllow, boolean forDeny, LocalRestriction restriction, boolean requireAllowOrDenyAlreadySet) throws RepositoryException {
        if (p.isAggregate()) {
            Privilege[] aggregatePrivileges = p.getDeclaredAggregatePrivileges();
            for (Privilege aggregatePrivilege : aggregatePrivileges) {
                if (aggregatePrivilege.isAggregate()) {
                    addRestrictionWithoutAggregates(privilegeToLocalPrivilegesMap, aggregatePrivilege, forAllow, forDeny, restriction, requireAllowOrDenyAlreadySet);
                } else {
                    localPrivAddRestriction(privilegeToLocalPrivilegesMap, aggregatePrivilege, forAllow, forDeny, restriction, requireAllowOrDenyAlreadySet);
                }
            }
        } else {
            localPrivAddRestriction(privilegeToLocalPrivilegesMap, p, forAllow, forDeny, restriction, requireAllowOrDenyAlreadySet);
        }
    }

    /**
     * Adds the restriction for each of the supplied allow privilege in the privilegeToLocalPrivilegesMap.
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param restriction the restrictions to add
     * @param privileges the privilege to update
     */
    public static void allowRestriction(@NotNull Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap,
            @NotNull LocalRestriction restriction, @NotNull Collection<Privilege> privileges) throws RepositoryException {
        for (Privilege privilege : privileges) {
            addRestrictionWithoutAggregates(privilegeToLocalPrivilegesMap, privilege, true, false, restriction, false);
        }
    }

    /**
     * Remove the restriction for each of the supplied allow privilege in the privilegeToLocalPrivilegesMap.
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param restrictionName the restriction name to remove
     * @param privileges the privilege to update
     */
    public static void unallowRestriction(@NotNull Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap,
            @NotNull String restrictionName, @NotNull Collection<Privilege> privileges) throws RepositoryException {
        unallowRestrictions(privilegeToLocalPrivilegesMap, Collections.singleton(restrictionName), privileges);
    }

    /**
     * Remove the restrictions for each of the supplied allow privilege in the privilegeToLocalPrivilegesMap.
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param restrictionNames the collection of restriction names to remove
     * @param privileges the privilege to update
     */
    public static void unallowRestrictions(@NotNull Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap,
            @NotNull Collection<String> restrictionNames, @NotNull Collection<Privilege> privileges) throws RepositoryException {
        for (Privilege privilege : privileges) {
            removeRestrictionsWithoutAggregates(privilegeToLocalPrivilegesMap, privilege, true, false, restrictionNames);
        }
    }

    /**
     * Adds the restriction for each of the supplied deny privilege in the privilegeToLocalPrivilegesMap.
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param restriction the restrictions to add
     * @param privileges the privilege to update
     */
    public static void denyRestriction(@NotNull Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap,
            @NotNull LocalRestriction restriction, @NotNull Collection<Privilege> privileges) throws RepositoryException {
        for (Privilege privilege : privileges) {
            addRestrictionWithoutAggregates(privilegeToLocalPrivilegesMap, privilege, false, true, restriction, false);
        }
    }

    /**
     * Remove the restriction for each of the supplied deny privilege in the privilegeToLocalPrivilegesMap.
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param restriction the restrictions to add
     * @param privileges the privilege to update
     */
    public static void undenyRestriction(@NotNull Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap,
            @NotNull String restrictionName, @NotNull Collection<Privilege> privileges) throws RepositoryException {
        undenyRestrictions(privilegeToLocalPrivilegesMap, Collections.singleton(restrictionName), privileges);
    }

    /**
     * Remove the restrictions for each of the supplied deny privilege in the privilegeToLocalPrivilegesMap.
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param restrictionNames the collection of restriction names to remove
     * @param privileges the privilege to update
     */
    public static void undenyRestrictions(@NotNull Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap,
            @NotNull Collection<String> restrictionNames, @NotNull Collection<Privilege> privileges) throws RepositoryException {
        for (Privilege privilege : privileges) {
            removeRestrictionsWithoutAggregates(privilegeToLocalPrivilegesMap, privilege, false, true, restrictionNames);
        }
    }

    /**
     * Adds the restriction for each of the supplied privilege in the privilegeToLocalPrivilegesMap that
     * is already has allow or deny set to true.
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param restriction the restrictions to add
     * @param privileges the privilege to update
     */
    public static void allowOrDenyRestriction(@NotNull Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap,
            @NotNull LocalRestriction restriction, @NotNull Collection<Privilege> privileges) throws RepositoryException {
        for (Privilege privilege : privileges) {
            addRestrictionWithoutAggregates(privilegeToLocalPrivilegesMap, privilege, true, true, restriction, true);
        }
    }

    /**
     * Remove the restriction for each of the supplied privilege in the privilegeToLocalPrivilegesMap that
     * is already has allow or deny set to true.
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param restriction the restrictions to add
     * @param privileges the privilege to update
     */
    public static void unallowOrUndenyRestriction(@NotNull Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap,
            @NotNull String restrictionName, @NotNull Collection<Privilege> privileges) throws RepositoryException {
        unallowOrUndenyRestrictions(privilegeToLocalPrivilegesMap, Collections.singleton(restrictionName), privileges);
    }

    /**
     * Remove the restrictions for each of the supplied privilege in the privilegeToLocalPrivilegesMap that
     * is already has allow or deny set to true.
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param restrictionNames the collection of restriction names to remove
     * @param privileges the privilege to update
     */
    public static void unallowOrUndenyRestrictions(@NotNull Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap,
            @NotNull Collection<String> restrictionNames, @NotNull Collection<Privilege> privileges) throws RepositoryException {
        for (Privilege privilege : privileges) {
            removeRestrictionsWithoutAggregates(privilegeToLocalPrivilegesMap, privilege, true, true, restrictionNames);
        }
    }

    /**
     * Calculates the supported privileges in the resource path exists, or the registered
     * privileges if the resource path does not exist
     * 
     * @param jcrSession the current session
     * @param resourcePath the resource path to consider
     * @return
     * @throws RepositoryException
     */
    private static @NotNull Privilege[] getSupportedOrRegisteredPrivileges(@NotNull Session jcrSession, @Nullable String resourcePath) 
            throws RepositoryException {
        Privilege[] supportedPrivileges = null;
        if (resourcePath != null && jcrSession.nodeExists(resourcePath)) {
            supportedPrivileges = jcrSession.getAccessControlManager().getSupportedPrivileges(resourcePath);
        } else {
            // non-existing path. We can't determine what is supported there, so consider all registered privileges
            Workspace workspace = jcrSession.getWorkspace();
            if (workspace instanceof JackrabbitWorkspace) {
                PrivilegeManager privilegeManager = ((JackrabbitWorkspace)workspace).getPrivilegeManager();
                supportedPrivileges = privilegeManager.getRegisteredPrivileges();
            }
        }
        return supportedPrivileges == null ? new Privilege[0] : supportedPrivileges;
    }

    /**
     * Process the supplied privileges and consolidate each aggregate whenever the state of all the
     * aggregated direct child privileges are allow or deny
     * 
     * @param jcrSession the current session
     * @param resourcePath the path of the resource
     * @param privilegeToLocalPrivilegesMap map of privileges to process. The map entry key is the
     *          privilege and value is the associated LocalPrivilege.
     * @param privilegeLongestDepthMap map of privileges to the longest depth.  See {@link #buildPrivilegeLongestDepthMap(Privilege)}
     */
    public static void consolidateAggregates(Session jcrSession, String resourcePath, 
            Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap,
            Map<Privilege, Integer> privilegeLongestDepthMap) throws RepositoryException {
        Privilege[] supportedPrivileges = getSupportedOrRegisteredPrivileges(jcrSession, resourcePath);
        // sort the aggregates to process the deepest first
        Privilege[] supportedAggregatePrivileges = Stream.of(supportedPrivileges)
                .filter(Privilege::isAggregate)
                .sorted((p1, p2) -> privilegeLongestDepthMap.get(p2).compareTo(privilegeLongestDepthMap.get(p1)))
                .toArray(size -> new Privilege[size]);
        // loop to consider each aggregate privilege
        for (Privilege aggregatePrivilege : supportedAggregatePrivileges) {
            // filter the declared aggregate privileges in case some are not a
            //   direct child.  For example, the jcr:all aggregate privileges list
            //   contains too many for this use case.
            int childDepth = privilegeLongestDepthMap.getOrDefault(aggregatePrivilege, -1) + 1;
            Privilege[] childPrivileges = Stream.of(aggregatePrivilege.getDeclaredAggregatePrivileges())
                    .filter(p -> privilegeLongestDepthMap.getOrDefault(p, -1) == childDepth)
                    .toArray(size -> new Privilege[size]);

            // map to LocalPrivileges if we have them
            List<LocalPrivilege> childLocalPrivileges = Stream.of(childPrivileges)
                    .filter(privilegeToLocalPrivilegesMap::containsKey)
                    .map(privilegeToLocalPrivilegesMap::get)
                    .collect(Collectors.toList());

            if (childPrivileges.length == childLocalPrivileges.size()) {
                boolean allAllow = childLocalPrivileges.stream().allMatch(LocalPrivilege::isAllow);
                if (allAllow) {
                    // all the child privileges are allow so we can mark the parent as allow
                    LocalPrivilege alp = privilegeToLocalPrivilegesMap.computeIfAbsent(aggregatePrivilege, LocalPrivilege::new);
                    alp.setAllow(true);

                    // if the restrictions of all the items is the same then we should copy it up
                    //  and unset the data from each child
                    Set<LocalRestriction> firstAllowRestrictions = childLocalPrivileges.get(0).getAllowRestrictions();
                    boolean allRestrictionsSame = childLocalPrivileges.stream().allMatch(lp -> firstAllowRestrictions.equals(lp.getAllowRestrictions()));
                    if (allRestrictionsSame) {
                        alp.setAllowRestrictions(firstAllowRestrictions);
                    }
                    // each child with the same restrictions can be unset
                    for (LocalPrivilege lp : childLocalPrivileges) {
                        if (lp.sameAllowRestrictions(alp.getAllowRestrictions())) {
                            lp.setAllow(false);
                            lp.setAllowRestrictions(Collections.emptySet());
                        }
                    }
                }
                boolean allDeny = childLocalPrivileges.stream().allMatch(LocalPrivilege::isDeny);
                if (allDeny) {
                    // all the child privileges are deny so we can mark the parent as deny
                    LocalPrivilege alp = privilegeToLocalPrivilegesMap.computeIfAbsent(aggregatePrivilege, LocalPrivilege::new);
                    alp.setDeny(true);

                    // if the restrictions of all the items is the same then we should copy it up
                    //  and unset the data from each child
                    Set<LocalRestriction> firstDenyRestrictions = childLocalPrivileges.get(0).getDenyRestrictions();
                    boolean allRestrictionsSame = childLocalPrivileges.stream().allMatch(lp -> firstDenyRestrictions.equals(lp.getDenyRestrictions()));
                    if (allRestrictionsSame) {
                        alp.setDenyRestrictions(firstDenyRestrictions);
                    }
                    // each child with the same restrictions can be unset
                    for (LocalPrivilege lp : childLocalPrivileges) {
                        if (lp.sameDenyRestrictions(alp.getDenyRestrictions())) {
                            lp.setDeny(false);
                            lp.setDenyRestrictions(Collections.emptySet());
                        }
                    }
                }
            }
        }

        // remove any entries that are neither allow nor deny
        privilegeToLocalPrivilegesMap.entrySet().removeIf(entry -> entry.getValue().isNone());
    }

}
