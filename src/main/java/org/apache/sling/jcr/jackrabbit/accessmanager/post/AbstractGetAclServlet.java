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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.security.AccessControlEntry;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.Privilege;
import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

import org.apache.jackrabbit.api.security.JackrabbitAccessControlEntry;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionDefinition;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.sling.jcr.base.util.AccessControlUtil;
import org.apache.sling.jcr.jackrabbit.accessmanager.LocalPrivilege;
import org.apache.sling.jcr.jackrabbit.accessmanager.LocalRestriction;
import org.apache.sling.jcr.jackrabbit.accessmanager.impl.JsonConvert;
import org.apache.sling.jcr.jackrabbit.accessmanager.impl.PrivilegesHelper;

@SuppressWarnings({"serial", "java:S110"})
public abstract class AbstractGetAclServlet extends AbstractAccessGetServlet {

    /**
     * @deprecated since 3.0.12, To be removed when the exported package version goes to 4.0
     *      use {@link JsonConvert#KEY_ORDER} instead
     */
    @Deprecated
    protected static final String KEY_ORDER = JsonConvert.KEY_ORDER;
    /**
     * @deprecated since 3.0.12, To be removed when the exported package version goes to 4.0
     */
    @Deprecated
    protected static final String KEY_DENIED = "denied";
    /**
     * @deprecated since 3.0.12, To be removed when the exported package version goes to 4.0
     */
    @Deprecated
    protected static final String KEY_GRANTED = "granted";

    @Override
    protected JsonObject internalJson(Session session, String resourcePath, String principalId) throws RepositoryException {
        return internalGetAcl(session, resourcePath);
    }

    protected JsonObject internalGetAcl(Session jcrSession, String resourcePath) throws RepositoryException {
        validateArgs(jcrSession, resourcePath);

        //make a temp map for quick lookup below
        Set<RestrictionDefinition> supportedRestrictions = getRestrictionProvider().getSupportedRestrictions(resourcePath);
        Map<String, RestrictionDefinition> srMap = new HashMap<>();
        for (RestrictionDefinition restrictionDefinition : supportedRestrictions) {
            srMap.put(restrictionDefinition.getName(), restrictionDefinition);
        }

        Map<Principal, Map<DeclarationType, Set<String>>> principalToDeclaredAtPaths = new HashMap<>();
        Map<String, List<AccessControlEntry>> effectivePathToEntriesMap = getAccessControlEntriesMap(jcrSession, resourcePath, principalToDeclaredAtPaths);
        Map<Principal, Integer> principalToOrderMap = new HashMap<>();
        Map<Principal, Map<Privilege, LocalPrivilege>> principalToPrivilegesMap = new HashMap<>();
        for (Entry<String, List<AccessControlEntry>> entry : effectivePathToEntriesMap.entrySet()) {
            List<AccessControlEntry> accessControlEntries = entry.getValue();
            for (AccessControlEntry accessControlEntry : accessControlEntries) {
                if (accessControlEntry instanceof JackrabbitAccessControlEntry) {
                    JackrabbitAccessControlEntry jrAccessControlEntry = (JackrabbitAccessControlEntry)accessControlEntry;
                    Privilege[] privileges = jrAccessControlEntry.getPrivileges();
                    if (privileges != null) {
                        Principal principal = accessControlEntry.getPrincipal();
                        if (!principalToPrivilegesMap.containsKey(principal)) {
                            principalToOrderMap.put(principal, principalToPrivilegesMap.size());
                        }
                        Map<Privilege, LocalPrivilege> map = principalToPrivilegesMap.computeIfAbsent(principal, k -> new HashMap<>());

                        processACE(srMap, jrAccessControlEntry, privileges, map);
                    }
                }
            }
        }

        // combine any aggregates that are still valid
        AccessControlManager acm = AccessControlUtil.getAccessControlManager(jcrSession);
        Map<Privilege, Integer> privilegeLongestDepthMap = PrivilegesHelper.buildPrivilegeLongestDepthMap(acm.privilegeFromName(PrivilegeConstants.JCR_ALL));
        for (Entry<Principal, Map<Privilege, LocalPrivilege>> entry : principalToPrivilegesMap.entrySet()) {
            Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap = entry.getValue();

            PrivilegesHelper.consolidateAggregates(jcrSession, resourcePath, privilegeToLocalPrivilegesMap, privilegeLongestDepthMap);
        }

        // sort the entries by the order value for readability
        List<Entry<Principal, Map<Privilege, LocalPrivilege>>> entrySetList = new ArrayList<>(principalToPrivilegesMap.entrySet());
        Collections.sort(entrySetList, (e1, e2) -> principalToOrderMap.get(e1.getKey()).compareTo(principalToOrderMap.get(e2.getKey())));

        // convert the data to JSON
        JsonObjectBuilder jsonObj = convertToJson(entrySetList, principalToDeclaredAtPaths);
        return jsonObj.build();
    }

    protected JsonObjectBuilder convertToJson(List<Entry<Principal, Map<Privilege, LocalPrivilege>>> entrySetList,
            Map<Principal, Map<DeclarationType, Set<String>>> declaredAtPaths) {
        JsonObjectBuilder jsonObj = Json.createObjectBuilder();
        for (int i = 0; i < entrySetList.size(); i++) {
            Entry<Principal, Map<Privilege, LocalPrivilege>> entry = entrySetList.get(i);
            Principal principal = entry.getKey();
            JsonObjectBuilder principalObj = JsonConvert.convertToJson(entry.getKey(), entry.getValue(), i);
            addExtraInfo(principalObj, principal, declaredAtPaths);
            jsonObj.add(principal.getName(), principalObj);
        }
        return jsonObj;
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


    /**
     * @deprecated use {@link JsonConvert#addRestrictions(JsonObjectBuilder, String, Set)} instead
     */
    @Deprecated
    protected void addRestrictions(JsonObjectBuilder privilegeObj, String key, Set<LocalRestriction> restrictions) {
        JsonConvert.addRestrictions(privilegeObj, key, restrictions);
    }

    /**
     * @deprecated use {@link JsonConvert#addTo(javax.json.JsonArrayBuilder, Object)} instead
     */
    @Deprecated
    protected JsonObjectBuilder addTo(JsonObjectBuilder builder, String key, Object value) {
        return JsonConvert.addTo(builder, key, value);
    }

    /**
     * @deprecated use {@link JsonConvert#addTo(JsonObjectBuilder, String, Object)} instead
     */
    @Deprecated
    protected JsonArrayBuilder addTo(JsonArrayBuilder builder, Object value) {
        return JsonConvert.addTo(builder, value);
    }

    protected abstract Map<String, List<AccessControlEntry>> getAccessControlEntriesMap(Session session, String absPath,
            Map<Principal, Map<DeclarationType, Set<String>>> declaredAtPaths) throws RepositoryException;

    /**
     * @deprecated use {@link #getAccessControlEntriesMap(Session, String, Map)} instead
     */
    @Deprecated
    protected AccessControlEntry[] getAccessControlEntries(Session session, String absPath) throws RepositoryException {
        return getAccessControlEntriesMap(session, absPath, new HashMap<>()).values().stream()
                .toArray(size -> new AccessControlEntry[size]);
    }

}
