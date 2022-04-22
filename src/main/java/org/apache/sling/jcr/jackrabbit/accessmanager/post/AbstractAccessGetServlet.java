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
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.jcr.AccessDeniedException;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.security.Privilege;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.stream.JsonGenerator;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.apache.jackrabbit.api.security.JackrabbitAccessControlEntry;
import org.apache.jackrabbit.api.security.principal.PrincipalManager;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionDefinition;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.resource.ResourceNotFoundException;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.jcr.base.util.AccessControlUtil;
import org.apache.sling.jcr.jackrabbit.accessmanager.LocalPrivilege;
import org.apache.sling.jcr.jackrabbit.accessmanager.LocalRestriction;
import org.apache.sling.jcr.jackrabbit.accessmanager.impl.PrivilegesHelper;
import org.jetbrains.annotations.NotNull;

@SuppressWarnings("serial")
public abstract class AbstractAccessGetServlet extends SlingAllMethodsServlet {

    private transient RestrictionProvider restrictionProvider;

    // @Reference
    protected void bindRestrictionProvider(RestrictionProvider rp) {
        this.restrictionProvider = rp;
    }

    /**
     * Return the RestrictionProvider service
     */
    protected RestrictionProvider getRestrictionProvider() {
        return restrictionProvider;
    }

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
            String principalId = request.getParameter("pid");

            JsonObject jsonObj = internalJson(session, resourcePath, principalId);
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
                generator.write(jsonObj).flush();
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

    protected abstract JsonObject internalJson(Session session, String resourcePath, String principalId) throws RepositoryException;

    /**
     * Verify that the user supplied arguments are valid
     * 
     * @param jcrSession the JCR session
     * @param resourcePath the resource path
     * @param principalId the principal id
     * @return the principal for the requested principalId
     */
    protected @NotNull Principal validateArgs(Session jcrSession, String resourcePath, String principalId) throws RepositoryException {
        validateArgs(jcrSession, resourcePath);

        if (principalId == null) {
            throw new RepositoryException("principalId was not submitted.");
        }

        // validate that the submitted name is valid
        PrincipalManager principalManager = AccessControlUtil.getPrincipalManager(jcrSession);
        Principal principal = principalManager.getPrincipal(principalId);
        if (principal == null) {
            throw new RepositoryException("Invalid principalId was submitted.");
        }

        return principal;
    }

    /**
     * Verify that the user supplied arguments are valid
     * 
     * @param jcrSession the JCR session
     * @param resourcePath the resource path
     * @param principalId the principal id
     * @return the principal for the requested principalId
     */
    protected @NotNull void validateArgs(Session jcrSession, String resourcePath) throws RepositoryException {
        if (jcrSession == null) {
            throw new RepositoryException("JCR Session not found");
        }

        if (resourcePath == null) {
            throw new ResourceNotFoundException("Resource path was not supplied.");
        }

        if (!jcrSession.nodeExists(resourcePath)) {
            throw new ResourceNotFoundException("Resource is not a JCR Node");
        }
    }

    protected void processACE(Map<String, RestrictionDefinition> srMap,
            JackrabbitAccessControlEntry jrAccessControlEntry, Privilege[] privileges,
            Map<Privilege, LocalPrivilege> map) throws RepositoryException {
        boolean isAllow = jrAccessControlEntry.isAllow();
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
