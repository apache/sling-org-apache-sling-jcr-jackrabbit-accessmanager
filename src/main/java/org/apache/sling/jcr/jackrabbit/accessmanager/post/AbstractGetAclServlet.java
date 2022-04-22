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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.jcr.AccessDeniedException;
import javax.jcr.Item;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.security.AccessControlEntry;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.Privilege;
import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.stream.JsonGenerator;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.apache.jackrabbit.api.security.JackrabbitAccessControlEntry;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionDefinition;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.resource.ResourceNotFoundException;
import org.apache.sling.jcr.base.util.AccessControlUtil;
import org.apache.sling.jcr.jackrabbit.accessmanager.LocalPrivilege;
import org.apache.sling.jcr.jackrabbit.accessmanager.LocalRestriction;
import org.apache.sling.jcr.jackrabbit.accessmanager.impl.JsonConvert;
import org.apache.sling.jcr.jackrabbit.accessmanager.impl.PrivilegesHelper;
import org.jetbrains.annotations.NotNull;

@SuppressWarnings("serial")
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

    /* (non-Javadoc)
     * @see org.apache.sling.api.servlets.SlingSafeMethodsServlet#doGet(org.apache.sling.api.SlingHttpServletRequest, org.apache.sling.api.SlingHttpServletResponse)
     */
    @Override
    protected void doGet(SlingHttpServletRequest request,
            SlingHttpServletResponse response) throws ServletException,
            IOException {

        try {
            Session session = request.getResourceResolver().adaptTo(Session.class);
            String resourcePath = request.getResource().getPath();

            JsonObject acl = internalGetAcl(session, resourcePath);
            response.setContentType("application/json");
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());

            boolean isTidy = false;
            final String[] selectors = request.getRequestPathInfo().getSelectors();
            if (selectors.length > 0) {
                for (final String level : selectors) {
                    if("tidy".equals(level)) {
                        isTidy = true;
                        break;
                    }
                }
            }

            Map<String, Object> options = new HashMap<>();
            options.put(JsonGenerator.PRETTY_PRINTING, isTidy);
            try (JsonGenerator generator = Json.createGeneratorFactory(options).createGenerator(response.getWriter())) {
                generator.write(acl).flush();
            }
        } catch (AccessDeniedException ade) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
        } catch (ResourceNotFoundException rnfe) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, rnfe.getMessage());
        } catch (Exception throwable) {
            throw new ServletException(String.format("Exception while handling GET %s with %s",
                                            request.getResource().getPath(), getClass().getName()),
                                        throwable);
        }
    }

    protected JsonObject internalGetAcl(Session jcrSession, String resourcePath) throws RepositoryException {

        if (jcrSession == null) {
            throw new RepositoryException("JCR Session not found");
        }

        Item item = jcrSession.getItem(resourcePath);
        if (item != null) {
            resourcePath = item.getPath();
        } else {
            throw new ResourceNotFoundException("Resource is not a JCR Node");
        }

        //make a temp map for quick lookup below
        Set<RestrictionDefinition> supportedRestrictions = getRestrictionProvider().getSupportedRestrictions(resourcePath);
        Map<String, RestrictionDefinition> srMap = new HashMap<>();
        for (RestrictionDefinition restrictionDefinition : supportedRestrictions) {
            srMap.put(restrictionDefinition.getName(), restrictionDefinition);
        }

        AccessControlEntry[] accessControlEntries = getAccessControlEntries(jcrSession, resourcePath);
        Map<Principal, Integer> principalToOrderMap = new HashMap<>();
        Map<Principal, Map<Privilege, LocalPrivilege>> principalToPrivilegesMap = new HashMap<>();
        //evaluate these in reverse order so the entries with highest specificity are processed last
        for (int i = accessControlEntries.length - 1; i >= 0; i--) {
            AccessControlEntry accessControlEntry = accessControlEntries[i];
            if (accessControlEntry instanceof JackrabbitAccessControlEntry) {
                JackrabbitAccessControlEntry jrAccessControlEntry = (JackrabbitAccessControlEntry)accessControlEntry;
                Privilege[] privileges = jrAccessControlEntry.getPrivileges();
                if (privileges != null) {
                    boolean isAllow = jrAccessControlEntry.isAllow();
                    Principal principal = accessControlEntry.getPrincipal();
                    principalToOrderMap.put(principal, i);
                    Map<Privilege, LocalPrivilege> map = principalToPrivilegesMap.computeIfAbsent(principal, k -> new HashMap<>());
                    // populate the declared restrictions
                    @NotNull
                    String[] restrictionNames = jrAccessControlEntry.getRestrictionNames();
                    Set<LocalRestriction> restrictionItems = new HashSet<>();
                    for (String restrictionName : restrictionNames) {
                        RestrictionDefinition rd = srMap.get(restrictionName);
                        boolean isMulti = rd.getRequiredType().isArray();
                        if (isMulti) {
                            restrictionItems.add(new LocalRestriction(rd, jrAccessControlEntry.getRestrictions(restrictionName)));
                        } else {
                            restrictionItems.add(new LocalRestriction(rd, jrAccessControlEntry.getRestriction(restrictionName)));
                        }
                    }

                    if (isAllow) {
                        PrivilegesHelper.allow(map, restrictionItems, Arrays.asList(privileges));
                    } else {
                        PrivilegesHelper.deny(map, restrictionItems, Arrays.asList(privileges));
                    }
                }
            }
        }

        // combine any aggregates that are still valid
        AccessControlManager acm = AccessControlUtil.getAccessControlManager(jcrSession);
        Map<Privilege, Integer> privilegeLongestDepthMap = PrivilegesHelper.buildPrivilegeLongestDepthMap(acm.privilegeFromName(PrivilegeConstants.JCR_ALL));
        for (Entry<Principal, Map<Privilege, LocalPrivilege>> entry : principalToPrivilegesMap.entrySet()) {
            Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap = entry.getValue();

            PrivilegesHelper.consolidateAggregates(acm, resourcePath, privilegeToLocalPrivilegesMap, privilegeLongestDepthMap);
        }

        // sort the entries by the order value for readability
        List<Entry<Principal, Map<Privilege, LocalPrivilege>>> entrySetList = new ArrayList<>(principalToPrivilegesMap.entrySet());
        Collections.sort(entrySetList, (e1, e2) -> principalToOrderMap.get(e1.getKey()).compareTo(principalToOrderMap.get(e2.getKey())));

        // convert the data to JSON
        JsonObjectBuilder jsonObj = convertToJson(entrySetList);
        return jsonObj.build();
    }


    protected JsonObjectBuilder convertToJson(List<Entry<Principal, Map<Privilege, LocalPrivilege>>> entrySetList) {
        JsonObjectBuilder jsonObj = Json.createObjectBuilder();
        for (int i = 0; i < entrySetList.size(); i++) {
            Entry<Principal, Map<Privilege, LocalPrivilege>> entry = entrySetList.get(i);
            Principal principal = entry.getKey();
            JsonObjectBuilder principalObj = JsonConvert.convertToJson(entry.getKey(), entry.getValue(), i);
            jsonObj.add(principal.getName(), principalObj);
        }
        return jsonObj;
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

    protected abstract AccessControlEntry[] getAccessControlEntries(Session session, String absPath) throws RepositoryException;

}
