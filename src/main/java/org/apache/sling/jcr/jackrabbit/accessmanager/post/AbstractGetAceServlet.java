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
package org.apache.sling.jcr.jackrabbit.accessmanager.post;

import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.security.AccessControlEntry;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.Privilege;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

import org.apache.jackrabbit.api.security.JackrabbitAccessControlEntry;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionDefinition;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.sling.api.resource.ResourceNotFoundException;
import org.apache.sling.jcr.base.util.AccessControlUtil;
import org.apache.sling.jcr.jackrabbit.accessmanager.LocalPrivilege;
import org.apache.sling.jcr.jackrabbit.accessmanager.impl.JsonConvert;
import org.apache.sling.jcr.jackrabbit.accessmanager.impl.PrivilegesHelper;

@SuppressWarnings("serial")
public abstract class AbstractGetAceServlet extends AbstractAccessGetServlet {

    @Override
    protected JsonObject internalJson(Session session, String resourcePath, String principalId) throws RepositoryException {
        return internalGetAce(session, resourcePath, principalId);
    }

    protected JsonObject internalGetAce(Session jcrSession, String resourcePath, String principalId) throws RepositoryException {
        Principal principal = validateArgs(jcrSession, resourcePath, principalId);

        Map<Principal, Map<DeclarationType, Set<String>>> principalToDeclaredAtPaths = new HashMap<>();
        Map<String, List<AccessControlEntry>> effectivePathToEntriesMap = getAccessControlEntriesMap(jcrSession, resourcePath, principal, principalToDeclaredAtPaths);
        if (effectivePathToEntriesMap == null || effectivePathToEntriesMap.isEmpty()) {
            throw new ResourceNotFoundException(resourcePath, "No access control entries were found");
        }

        //make a temp map for quick lookup below
        Set<RestrictionDefinition> supportedRestrictions = getRestrictionProvider().getSupportedRestrictions(resourcePath);
        Map<String, RestrictionDefinition> srMap = new HashMap<>();
        for (RestrictionDefinition restrictionDefinition : supportedRestrictions) {
            srMap.put(restrictionDefinition.getName(), restrictionDefinition);
        }

        Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap = new HashMap<>();
        for (List<AccessControlEntry> accessControlEntries : effectivePathToEntriesMap.values()) {
            for (AccessControlEntry accessControlEntry : accessControlEntries) {
                if (accessControlEntry instanceof JackrabbitAccessControlEntry) {
                    JackrabbitAccessControlEntry jrAccessControlEntry = (JackrabbitAccessControlEntry)accessControlEntry;
                    Privilege[] privileges = jrAccessControlEntry.getPrivileges();
                    if (privileges != null) {
                        processACE(srMap, jrAccessControlEntry, privileges, privilegeToLocalPrivilegesMap);
                    }
                }
            }
        }

        // combine any aggregates that are still valid
        AccessControlManager acm = AccessControlUtil.getAccessControlManager(jcrSession);
        Map<Privilege, Integer> privilegeLongestDepthMap = PrivilegesHelper.buildPrivilegeLongestDepthMap(acm.privilegeFromName(PrivilegeConstants.JCR_ALL));
        PrivilegesHelper.consolidateAggregates(jcrSession, resourcePath, privilegeToLocalPrivilegesMap, privilegeLongestDepthMap);

        // convert the data to JSON
        JsonObjectBuilder principalObj = JsonConvert.convertToJson(principal, privilegeToLocalPrivilegesMap, -1);
        addExtraInfo(principalObj, principal, principalToDeclaredAtPaths);
        return principalObj.build();
    }

    /**
     * Override to add additional data to the principal object
     * 
     * @param principalObj the current principal object
     * @param principal the current principal
     * @param principalToDeclaredAtPaths a map of principal the paths where ACEs are declared
     */
    protected void addExtraInfo(JsonObjectBuilder principalJson,
            Principal principal, Map<Principal, Map<DeclarationType, Set<String>>> principalToDeclaredAtPaths) {
        // no-op 
    }

    protected abstract Map<String, List<AccessControlEntry>> getAccessControlEntriesMap(Session session, String absPath, Principal principal,
            Map<Principal, Map<DeclarationType, Set<String>>> declaredAtPaths) throws RepositoryException;

    /**
     * @deprecated use {@link #getAccessControlEntriesMap(Session, String, Principal, Map)} instead
     */
    @Deprecated
    protected AccessControlEntry[] getAccessControlEntries(Session session, String absPath, Principal principal) throws RepositoryException {
        return getAccessControlEntriesMap(session, absPath, principal, new HashMap<>()).values().stream()
            .toArray(size -> new AccessControlEntry[size]);
    }

}
