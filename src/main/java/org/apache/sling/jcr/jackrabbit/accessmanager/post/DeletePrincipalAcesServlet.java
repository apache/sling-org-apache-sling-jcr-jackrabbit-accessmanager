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

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.security.AccessControlEntry;
import javax.jcr.security.AccessControlPolicy;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import jakarta.servlet.Servlet;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlManager;
import org.apache.jackrabbit.api.security.authorization.PrincipalAccessControlList;
import org.apache.sling.jcr.jackrabbit.accessmanager.DeletePrincipalAces;
import org.apache.sling.jcr.jackrabbit.accessmanager.impl.PrincipalAceHelper;
import org.apache.sling.servlets.post.JakartaPostResponseCreator;
import org.apache.sling.servlets.post.Modification;
import org.jetbrains.annotations.NotNull;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicyOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * Sling Post Servlet implementation for deleting the principal ACE for a set of principals on a JCR
 * resource.
 * </p>
 * <h2>Rest Service Description</h2>
 * <p>
 * Delete a set of Ace's from a node, the node is identified as a resource by the request
 * url &gt;resource&lt;.deletePAce.html
 * </p>
 * <h3>Transport Details:</h3>
 * <h4>Methods</h4>
 * <ul>
 * <li>POST</li>
 * </ul>
 * <h4>Post Parameters</h4>
 * <dl>
 * <dt>:applyTo</dt>
 * <dd>An array of ace principal names to delete. Note the principal name is the primary
 * key of the Ace in the Acl</dd>
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
 */
@Component(
        service = {Servlet.class, DeletePrincipalAces.class},
        property = {
            "sling.servlet.resourceTypes=sling/servlet/default",
            "sling.servlet.methods=POST",
            "sling.servlet.selectors=deletePAce",
            "sling.servlet.prefix:Integer=-1"
        },
        reference = {
            @Reference(
                    name = "PostResponseCreator",
                    bind = "bindPostResponseCreator",
                    cardinality = ReferenceCardinality.MULTIPLE,
                    policyOption = ReferencePolicyOption.GREEDY,
                    service = JakartaPostResponseCreator.class)
        })
@SuppressWarnings("java:S110")
public class DeletePrincipalAcesServlet extends DeleteAcesServlet implements DeletePrincipalAces {
    private static final long serialVersionUID = 3784866802938282971L;

    /**
     * default log
     */
    private final transient Logger log = LoggerFactory.getLogger(getClass());

    @Override
    protected boolean allowNonExistingPaths() {
        return true;
    }

    @Override
    public void deletePrincipalAces(Session jcrSession, String resourcePath, String[] principalNamesToDelete)
            throws RepositoryException {
        deleteAces(jcrSession, resourcePath, principalNamesToDelete, null);
    }

    @Override
    protected void deleteAces(
            Session jcrSession, String resourcePath, String[] principalNamesToDelete, List<Modification> changes)
            throws RepositoryException {
        @NotNull Set<Principal> found = validateArgs(jcrSession, resourcePath, principalNamesToDelete);
        try {
            JackrabbitAccessControlManager jacm = (JackrabbitAccessControlManager) jcrSession.getAccessControlManager();

            // track which of the submitted principals had an ACE removed
            Set<Principal> removedPrincipalSet = new HashSet<>();

            // log the warning about principals where no ACE was found
            for (Principal principal : found) {
                PrincipalAccessControlList updatedAcl = getAccessControlListOrNull(jacm, principal);

                // if there is no AccessControlList, then there is nothing to be deleted
                if (updatedAcl == null) {
                    // log the warning about principals where no ACE was found
                    log.warn("No AccessControlEntry was found to be deleted for principal: {}", principal.getName());
                } else {
                    // keep track of the existing Aces for the target principal
                    AccessControlEntry[] accessControlEntries = Stream.of(updatedAcl.getAccessControlEntries())
                            .filter(entry -> entry instanceof PrincipalAccessControlList.Entry
                                    && PrincipalAceHelper.matchesResourcePath(resourcePath, entry))
                            .toArray(size -> new AccessControlEntry[size]);

                    List<AccessControlEntry> oldAces = new ArrayList<>();
                    for (AccessControlEntry ace : accessControlEntries) {
                        if (found.contains(ace.getPrincipal())) {
                            oldAces.add(ace);
                        }
                    }

                    // remove the old aces
                    if (!oldAces.isEmpty()) {
                        for (AccessControlEntry ace : oldAces) {
                            updatedAcl.removeAccessControlEntry(ace);

                            // remove from the candidate set
                            removedPrincipalSet.add(ace.getPrincipal());
                        }
                    }

                    // log the warning about principals where no ACE was found
                    if (removedPrincipalSet.contains(principal)) {
                        if (changes != null) {
                            changes.add(Modification.onDeleted(principal.getName()));
                        }
                    } else {
                        log.warn(
                                "No AccessControlEntry was found to be deleted for principal: {}", principal.getName());
                    }

                    // apply the changed policy
                    jacm.setPolicy(updatedAcl.getPath(), updatedAcl);
                }
            }
        } catch (RepositoryException re) {
            throw new RepositoryException("Failed to delete access control.", re);
        }
    }

    protected PrincipalAccessControlList getAccessControlListOrNull(
            JackrabbitAccessControlManager jacm, Principal principal) throws RepositoryException {
        PrincipalAccessControlList acl = null;
        // check for an existing access control list to edit
        AccessControlPolicy[] policies = jacm.getPolicies(principal);
        for (AccessControlPolicy policy : policies) {
            if (policy instanceof PrincipalAccessControlList pacList) {
                acl = pacList;
            }
        }
        return acl;
    }
}
