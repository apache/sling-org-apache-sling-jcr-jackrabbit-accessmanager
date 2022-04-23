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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.security.AccessControlEntry;
import javax.jcr.security.AccessControlList;
import javax.jcr.security.AccessControlManager;
import javax.servlet.Servlet;

import org.apache.jackrabbit.api.security.principal.PrincipalManager;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.resource.ResourceNotFoundException;
import org.apache.sling.jcr.base.util.AccessControlUtil;
import org.apache.sling.jcr.jackrabbit.accessmanager.DeleteAces;
import org.apache.sling.servlets.post.Modification;
import org.apache.sling.servlets.post.PostResponse;
import org.apache.sling.servlets.post.PostResponseCreator;
import org.apache.sling.servlets.post.SlingPostConstants;
import org.jetbrains.annotations.NotNull;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * Sling Post Servlet implementation for deleting the ACE for a set of principals on a JCR
 * resource.
 * </p>
 * <h2>Rest Service Description</h2>
 * <p>
 * Delete a set of Ace's from a node, the node is identified as a resource by the request
 * url &gt;resource&lt;.deleteAce.html
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

@Component(service = {Servlet.class, DeleteAces.class},
    property= {
            "sling.servlet.resourceTypes=sling/servlet/default",
            "sling.servlet.methods=POST",
            "sling.servlet.selectors=deleteAce",
            "sling.servlet.prefix:Integer=-1"
    })
public class DeleteAcesServlet extends AbstractAccessPostServlet implements DeleteAces {
    private static final long serialVersionUID = 3784866802938282971L;

    /**
     * default log
     */
    private final transient Logger log = LoggerFactory.getLogger(getClass());

    /**
     * Overridden since the @Reference annotation is not inherited from the super method
     */
    @Override
    @Reference(service = PostResponseCreator.class,
        cardinality = ReferenceCardinality.MULTIPLE,
        policy = ReferencePolicy.DYNAMIC)
    protected void bindPostResponseCreator(PostResponseCreator creator, Map<String, Object> properties) {
        super.bindPostResponseCreator(creator, properties);
    }

    /* (non-Javadoc)
     * @see org.apache.sling.jackrabbit.usermanager.impl.post.AbstractPostServlet#unbindPostResponseCreator(org.apache.sling.servlets.post.PostResponseCreator, java.util.Map)
     */
    @Override
    protected void unbindPostResponseCreator(PostResponseCreator creator, Map<String, Object> properties) { //NOSONAR
        super.unbindPostResponseCreator(creator, properties);
    }

    /* (non-Javadoc)
     * @see org.apache.sling.jackrabbit.accessmanager.post.AbstractAccessPostServlet#handleOperation(org.apache.sling.api.SlingHttpServletRequest, org.apache.sling.servlets.post.PostResponse, java.util.List)
     */
    @Override
    protected void handleOperation(SlingHttpServletRequest request,
            PostResponse htmlResponse, List<Modification> changes)
            throws RepositoryException {

        Session session = request.getResourceResolver().adaptTo(Session.class);
        String resourcePath = request.getResource().getPath();
        String[] applyTo = request.getParameterValues(SlingPostConstants.RP_APPLY_TO);
        deleteAces(session, resourcePath, applyTo, changes);
    }

    /* (non-Javadoc)
     * @see org.apache.sling.jcr.jackrabbit.accessmanager.DeleteAces#deleteAces(javax.jcr.Session, java.lang.String, java.lang.String[])
     */
    public void deleteAces(Session jcrSession, String resourcePath,
            String[] principalNamesToDelete) throws RepositoryException {
        deleteAces(jcrSession, resourcePath, principalNamesToDelete, null);
    }

    /**
     * Verify that the user supplied arguments are valid
     * 
     * @param jcrSession the JCR session
     * @param resourcePath the resource path
     * @param principalNamesToDelete the principal ids to delelete
     * @return the principals for the requested principalIds
     */
    protected @NotNull Set<Principal> validateArgs(Session jcrSession, String resourcePath, String[] principalNamesToDelete) throws RepositoryException {
        Set<Principal> found = new HashSet<>();
        if (principalNamesToDelete == null) {
            throw new RepositoryException("principalIds were not sumitted.");
        } else {
            if (jcrSession == null) {
                throw new RepositoryException("JCR Session not found");
            }

            if (resourcePath == null) {
                throw new ResourceNotFoundException("Resource path was not supplied.");
            }

            if (!jcrSession.nodeExists(resourcePath)) {
                throw new ResourceNotFoundException("Resource is not a JCR Node");
            }

            // validate that the submitted names are valid
            Set<String> notFound = null;
            PrincipalManager principalManager = AccessControlUtil.getPrincipalManager(jcrSession);
            for (String pid : principalNamesToDelete) {
                Principal principal = principalManager.getPrincipal(pid);
                if (principal == null) {
                    if (notFound == null) {
                        notFound = new HashSet<>();
                    }
                    notFound.add(pid);
                } else {
                    found.add(principal);
                }
            }
            if (notFound != null && !notFound.isEmpty()) {
                throw new RepositoryException("Invalid principalId was submitted.");
            }
        }
        return found;
    }

    /* (non-Javadoc)
     * @see org.apache.sling.jcr.jackrabbit.accessmanager.DeleteAces#deleteAces(javax.jcr.Session, java.lang.String, java.lang.String[])
     */
    protected void deleteAces(Session jcrSession, String resourcePath,
            String[] principalNamesToDelete, List<Modification> changes) throws RepositoryException {
        @NotNull
        Set<Principal> found = validateArgs(jcrSession, resourcePath, principalNamesToDelete);
        try {
            AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(jcrSession);
            AccessControlList updatedAcl = getAccessControlListOrNull(accessControlManager, resourcePath, false);

            // if there is no AccessControlList, then there is nothing to be deleted
            if (updatedAcl == null) {
                // log the warning about principals where no ACE was found
                for (Principal principal : found) {
                    log.warn("No AccessControlEntry was found to be deleted for principal: {}", principal.getName());
                }
            } else {
                //keep track of the existing Aces for the target principal
                AccessControlEntry[] accessControlEntries = updatedAcl.getAccessControlEntries();
                List<AccessControlEntry> oldAces = new ArrayList<>();
                for (AccessControlEntry ace : accessControlEntries) {
                    if (found.contains(ace.getPrincipal())) {
                        oldAces.add(ace);
                    }
                }

                // track which of the submitted principals had an ACE removed
                Set<Principal> removedPrincipalSet = new HashSet<>();

                //remove the old aces
                if (!oldAces.isEmpty()) {
                    for (AccessControlEntry ace : oldAces) {
                        updatedAcl.removeAccessControlEntry(ace);

                        // remove from the candidate set
                        removedPrincipalSet.add(ace.getPrincipal());
                    }
                }

                // log the warning about principals where no ACE was found
                for (Principal principal : found) {
                    if (removedPrincipalSet.contains(principal)) {
                        if (changes != null) {
                            changes.add(Modification.onDeleted(principal.getName()));
                        }
                    } else {
                        log.warn("No AccessControlEntry was found to be deleted for principal: {}", principal.getName());
                    }
                }

                //apply the changed policy
                accessControlManager.setPolicy(resourcePath, updatedAcl);
            }
        } catch (RepositoryException re) {
            throw new RepositoryException("Failed to delete access control.", re);
        }
    }

}
