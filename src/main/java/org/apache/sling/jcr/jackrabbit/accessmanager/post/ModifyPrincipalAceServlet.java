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

import java.security.Principal;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.Value;
import javax.jcr.security.AccessControlEntry;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.AccessControlPolicy;
import javax.jcr.security.Privilege;

import org.apache.jackrabbit.api.security.JackrabbitAccessControlEntry;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlList;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlManager;
import org.apache.jackrabbit.api.security.authorization.PrincipalAccessControlList;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.sling.jcr.jackrabbit.accessmanager.LocalPrivilege;
import org.apache.sling.jcr.jackrabbit.accessmanager.LocalRestriction;
import org.apache.sling.jcr.jackrabbit.accessmanager.ModifyPrincipalAce;
import org.apache.sling.jcr.jackrabbit.accessmanager.impl.PrincipalAceHelper;
import org.apache.sling.servlets.post.JakartaPostResponseCreator;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicyOption;

import jakarta.servlet.Servlet;

/**
 * <p>
 * Sling Post Servlet implementation for modifying the principalbased ACE for a principal on a JCR
 * resource.
 * </p>
 * <h2>Rest Service Description</h2>
 * <p>
 * Modify a principal's ACEs for the node identified as a resource by the request
 * URL &gt;resource&lt;.modifyPAce.html
 * </p>
 * <h3>Transport Details:</h3>
 * <h4>Methods</h4>
 * <ul>
 * <li>POST</li>
 * </ul>
 * <h4>Post Parameters</h4>
 * <dl>
 * <dt>principalId</dt>
 * <dd>The principal of the ACEs to modify in the ACL specified by the path.</dd>
 * <dt>privilege@[privilege_name]</dt>
 * <dd>One or more privileges which will be applied to the ACE. Any permissions that are present in an
 * existing ACE for the principal but not in the request are left untouched. The parameter value must be either 'allow' or 'all'. 
 * For backward compatibility, 'granted' may also be used for the parameter value as an alias for 'allow'.</dd>
 * <dt>restriction@[restriction_name]</dt>
 * <dd>One or more restrictions which will be applied to the ACE. The value is the target value of the restriction to be set.</dd>
 * <dt>restriction@[restriction_name]@Delete</dt>
 * <dd>One or more restrictions which will be removed from the ACE</dd>
 * <dt>privilege@[privilege_name]@Delete</dt>
 * <dd>One param for each privilege to delete. The parameter value must be either 'allow' or 'all' to specify which state to delete from</dd>
 * <dt>restriction@[privilege_name]@[restriction_name]@Allow</dt>
 * <dt>restriction@[privilege_name]@[restriction_name]@Deny</dt>
 * <dd>One param for each restriction value. The same parameter name may be used again for multi-value restrictions. The @Allow suffix 
 *     specifies whether to apply the restriction to the 'allow' privilege.  The value is the target value of the restriction to be set.</dd>
 * <dt>restriction@[privilege_name]@[restriction_name]@Delete</dt>
 * <dd>One param for each restriction to delete. The parameter value must be either 'allow' or 'all' to specify which state to delete from.</dd>
 * </dl>
 *
 * <h4>Response</h4>
 * <dl>
 * <dt>200</dt>
 * <dd>Success.</dd>
 * <dt>404</dt>
 * <dd>The resource was not found.</dd>
 * <dt>500</dt>
 * <dd>Failure. HTML explains the failure.</dd>
 * </dl>
 *
 * <h4>Notes</h4>
 * <p>
 * The principalId is assumed to refer directly to an Authorizable, that comes direct from
 * the UserManager. This can be a group or a user, but if its a group, denied permissions
 * will not be added to the group. The group will only contain granted privileges.
 * </p>
 */
@Component(service = {Servlet.class, ModifyPrincipalAce.class},
property= {
        "sling.servlet.resourceTypes=sling/servlet/default",
        "sling.servlet.methods=POST",
        "sling.servlet.selectors=modifyPAce",
        "sling.servlet.prefix:Integer=-1"
},
reference = {
        @Reference(name="RestrictionProvider",
                bind = "bindRestrictionProvider",
                cardinality = ReferenceCardinality.MULTIPLE,
                policyOption = ReferencePolicyOption.GREEDY,
                service = RestrictionProvider.class),
        @Reference(name = "PostResponseCreator",
                bind = "bindPostResponseCreator",
                cardinality = ReferenceCardinality.MULTIPLE,
                policyOption = ReferencePolicyOption.GREEDY,
                service = JakartaPostResponseCreator.class)
})
@SuppressWarnings("java:S110")
public class ModifyPrincipalAceServlet extends ModifyAceServlet implements ModifyPrincipalAce {

    private static final long serialVersionUID = -4152308935573740745L;

    @Override
    protected boolean allowNonExistingPaths() {
        return true;
    }

    @Override
    public void modifyPrincipalAce(Session jcrSession, String resourcePath, String principalId,
            Map<String, String> privileges, boolean autoSave) throws RepositoryException {
        modifyPrincipalAce(jcrSession, resourcePath, principalId, privileges,
                null, null, null, autoSave);
    }

    @Override
    public void modifyPrincipalAce(Session jcrSession, String resourcePath, String principalId,
            Map<String, String> privileges, Map<String, Value> restrictions,
            Map<String, Value[]> mvRestrictions, Set<String> removeRestrictionNames, boolean autoSave)
            throws RepositoryException {
        modifyAce(jcrSession, resourcePath, principalId, privileges, null,
                restrictions, mvRestrictions, removeRestrictionNames, autoSave, null);
    }

    @Override
    public void modifyPrincipalAce(Session jcrSession, String resourcePath, String principalId,
            Collection<LocalPrivilege> localPrivileges, boolean autoSave) throws RepositoryException {
        modifyAce(jcrSession, resourcePath, principalId,
                localPrivileges, null,
                autoSave, null);
    }

    /**
     * Override to ensure that we get the policy that implements {@link PrincipalAccessControlList}
     */
    @Override
    protected JackrabbitAccessControlList getAcl(@NotNull AccessControlManager acm, String resourcePath, Principal principal)
            throws RepositoryException {
        JackrabbitAccessControlList acl = null;
        if (acm instanceof JackrabbitAccessControlManager) {
            JackrabbitAccessControlManager jacm = (JackrabbitAccessControlManager)acm;
            AccessControlPolicy[] policies = jacm.getPolicies(principal);
            for (AccessControlPolicy policy : policies) {
                if (policy instanceof PrincipalAccessControlList) {
                    acl = (PrincipalAccessControlList) policy;
                    break;
                }
            }
            if (acl == null) {
                AccessControlPolicy[]  applicablePolicies = jacm.getApplicablePolicies(principal);
                for (AccessControlPolicy policy : applicablePolicies) {
                    if (policy instanceof PrincipalAccessControlList) {
                        acl = (PrincipalAccessControlList) policy;
                        break;
                    }
                }
            }
        }
        return acl;
    }

    /**
     * Override to ensure that we only remove the entries that have an effectivePath that matches
     * the current resourcePath
     */
    @Override
    protected String removeAces(@NotNull String resourcePath, @Nullable String order, @NotNull Principal principal,
            @NotNull JackrabbitAccessControlList acl) throws RepositoryException {
        AccessControlEntry[] existingAccessControlEntries = acl.getAccessControlEntries();
        for (int j = 0; j < existingAccessControlEntries.length; j++) {
            AccessControlEntry ace = existingAccessControlEntries[j];
            @Nullable
            JackrabbitAccessControlEntry jrEntry = getJackrabbitAccessControlEntry(ace, resourcePath, principal);
            if (jrEntry != null) {
                if (order == null || order.length() == 0) {
                    //order not specified, so keep track of the original ACE position.
                    order = String.valueOf(j);
                }

                acl.removeAccessControlEntry(ace);
            }
        }
        return order;
    }

    /**
     * Override to ensure we do not add enty that denies privileges which is not allowed in a principal ACE
     */
    @Override
    protected void addAces(@NotNull String resourcePath, @NotNull Principal principal,
            @NotNull Map<Set<LocalRestriction>, List<LocalPrivilege>> restrictionsToLocalPrivilegesMap, boolean isAllow,
            @NotNull JackrabbitAccessControlList acl, Map<Privilege, Integer> privilegeLongestDepthMap)
            throws RepositoryException {
        if (isAllow) {
            super.addAces(resourcePath, principal, restrictionsToLocalPrivilegesMap, isAllow, acl, privilegeLongestDepthMap);
        } else if (!restrictionsToLocalPrivilegesMap.isEmpty()) {
            // deny privileges not allowed in a principal ACE
            throw new IllegalArgumentException("Deny privileges are not allowed in a principal ACE");
        }
    }

    /**
     * Override to ensure that we only return the entries that have an effectivePath that matches
     * the current resourcePath
     */
    @Override
    protected @Nullable JackrabbitAccessControlEntry getJackrabbitAccessControlEntry(@NotNull AccessControlEntry entry, @NotNull String resourcePath,
            @NotNull Principal forPrincipal) {
        JackrabbitAccessControlEntry jrEntry = null;
        if (entry instanceof PrincipalAccessControlList.Entry &&
                entry.getPrincipal().equals(forPrincipal) &&
                PrincipalAceHelper.matchesResourcePath(resourcePath, entry)) {
            jrEntry = (JackrabbitAccessControlEntry)entry;
        }
        return jrEntry;
    }

}
