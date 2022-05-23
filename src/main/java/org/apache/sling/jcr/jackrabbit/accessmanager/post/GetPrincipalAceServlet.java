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
package org.apache.sling.jcr.jackrabbit.accessmanager.post;

import java.security.Principal;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.security.AccessControlEntry;
import javax.jcr.security.AccessControlManager;
import javax.json.JsonObject;
import javax.servlet.Servlet;

import org.apache.jackrabbit.api.security.JackrabbitAccessControlEntry;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlManager;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlPolicy;
import org.apache.jackrabbit.api.security.authorization.PrincipalAccessControlList;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.jcr.jackrabbit.accessmanager.GetPrincipalAce;
import org.apache.sling.jcr.jackrabbit.accessmanager.impl.PrincipalAceHelper;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicyOption;

/**
 * <p>
 * Sling Get Servlet implementation for getting the principal based ACE for a principal on a JCR
 * resource.
 * </p>
 * <h2>Rest Service Description</h2>
 * <p>
 * Get a principal's ACE for the node identified as a resource by the request
 * URL &gt;resource&lt;.pace.json?pid=[principal_id]
 * </p>
 * <h3>Transport Details:</h3>
 * <h4>Methods</h4>
 * <ul>
 * <li>GET</li>
 * </ul>
 * <h4>Get Parameters</h4>
 * <dl>
 * <dt>pid</dt>
 * <dd>The principal id of the ACE to get in the principal ACL specified by the path.</dd>
 * </dl>
 *
 * <h4>Response</h4>
 * <dl>
 * <dt>200</dt>
 * <dd>Success.</dd>
 * <dt>404</dt>
 * <dd>The resource was not found or no access control entries exist for the principal.</dd>
 * <dt>500</dt>
 * <dd>Failure. JSON explains the failure.</dd>
 * </dl>
 */
@Component(service = {Servlet.class, GetPrincipalAce.class},
property= {
        "sling.servlet.resourceTypes=sling/servlet/default",
        "sling.servlet.methods=GET",
        "sling.servlet.selectors=pace",
        "sling.servlet.selectors=tidy.pace",
        "sling.servlet.extensions=json",
        "sling.servlet.prefix:Integer=-1"
},
reference = {
        @Reference(name="RestrictionProvider",
                bind = "bindRestrictionProvider",
                cardinality = ReferenceCardinality.MULTIPLE,
                policyOption = ReferencePolicyOption.GREEDY,
                service = RestrictionProvider.class)
}
)
@SuppressWarnings("java:S110")
public class GetPrincipalAceServlet extends AbstractGetAceServlet implements GetPrincipalAce {
    private static final long serialVersionUID = 1654062732084983394L;

    @Override
    protected @Nullable String getItemPath(SlingHttpServletRequest request) {
        return PrincipalAceHelper.getEffectivePath(request);
    }

    @Override
    protected void validateResourcePath(Session jcrSession, String resourcePath) throws RepositoryException {
        // path does not need to already exist for a principal ACE
    }

    @Override
    public JsonObject getPrincipalAce(Session jcrSession, String resourcePath, String principalId)
            throws RepositoryException {
        return internalGetAce(jcrSession, resourcePath, principalId);
    }

    @Override
    protected Map<String, List<AccessControlEntry>> getAccessControlEntriesMap(Session session, String absPath,
            Principal principal, Map<Principal, Map<DeclarationType, Set<String>>> declaredAtPaths) throws RepositoryException {
        AccessControlManager acMgr = session.getAccessControlManager();
        if (acMgr instanceof JackrabbitAccessControlManager) {
            JackrabbitAccessControlManager jacMgr = (JackrabbitAccessControlManager)acMgr;
            JackrabbitAccessControlPolicy[] policies = jacMgr.getPolicies(principal);
            return entriesSortedByEffectivePath(policies, ace -> matchesPrincipalAccessControlEntry(ace, absPath, principal), declaredAtPaths);
        } else {
            return Collections.emptyMap();
        }
    }

    /**
     * Checks if the entry is for the specified principal and the effective path is
     * equal to the resourcePath
     * 
     * @param entry the ACE to check
     * @param resourcePath the resource path
     * @param forPrincipal the principal
     * @return true for a match, false otherwise
     */
    protected boolean matchesPrincipalAccessControlEntry(@NotNull AccessControlEntry entry, @NotNull String resourcePath,
            @NotNull Principal forPrincipal) {
        JackrabbitAccessControlEntry jrEntry = null;
        if (entry instanceof PrincipalAccessControlList.Entry &&
                entry.getPrincipal().equals(forPrincipal) &&
                PrincipalAceHelper.matchesResourcePath(resourcePath, entry)) {
            jrEntry = (JackrabbitAccessControlEntry)entry;
        }
        return jrEntry != null;
    }

}
