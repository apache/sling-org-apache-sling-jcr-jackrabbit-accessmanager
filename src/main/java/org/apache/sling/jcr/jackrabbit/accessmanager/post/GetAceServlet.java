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
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.security.AccessControlEntry;
import javax.jcr.security.AccessControlList;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.AccessControlPolicy;
import javax.json.JsonObject;
import javax.servlet.Servlet;

import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.sling.jcr.base.util.AccessControlUtil;
import org.apache.sling.jcr.jackrabbit.accessmanager.GetAce;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

/**
 * <p>
 * Sling Get Servlet implementation for getting the ACE for a principal on a JCR
 * resource.
 * </p>
 * <h2>Rest Service Description</h2>
 * <p>
 * Get a principal's ACE for the node identified as a resource by the request
 * URL &gt;resource&lt;.ace.json?pid=[principal_id]
 * </p>
 * <h3>Transport Details:</h3>
 * <h4>Methods</h4>
 * <ul>
 * <li>GET</li>
 * </ul>
 * <h4>Get Parameters</h4>
 * <dl>
 * <dt>pid</dt>
 * <dd>The principal id of the ACE to get in the ACL specified by the path.</dd>
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
@Component(service = {Servlet.class, GetAce.class},
property= {
        "sling.servlet.resourceTypes=sling/servlet/default",
        "sling.servlet.methods=GET",
        "sling.servlet.selectors=ace",
        "sling.servlet.selectors=tidy.ace",
        "sling.servlet.extensions=json",
        "sling.servlet.prefix:Integer=-1"
},
reference = {
        @Reference(name="RestrictionProvider",
                bind = "bindRestrictionProvider",
                service = RestrictionProvider.class)
}
)
@SuppressWarnings("java:S110")
public class GetAceServlet extends AbstractGetAceServlet implements GetAce {
    private static final long serialVersionUID = 1654062732084983394L;

    @Override
    public JsonObject getAce(Session jcrSession, String resourcePath, String principalId)
            throws RepositoryException {
        return internalGetAce(jcrSession, resourcePath, principalId);
    }

    @Override
    protected AccessControlEntry[] getAccessControlEntries(Session session, String absPath, Principal principal) throws RepositoryException {
        AccessControlManager acMgr = AccessControlUtil.getAccessControlManager(session);
        AccessControlPolicy[] policies = acMgr.getPolicies(absPath);
        List<AccessControlEntry> allEntries = new ArrayList<>(); 
        for (AccessControlPolicy accessControlPolicy : policies) {
            if (accessControlPolicy instanceof AccessControlList) {
                AccessControlEntry[] accessControlEntries = ((AccessControlList)accessControlPolicy).getAccessControlEntries();
                Stream.of(accessControlEntries)
                    .filter(entry -> principal.equals(entry.getPrincipal()))
                    .forEach(allEntries::add);
            }
        }
        return allEntries.toArray(new AccessControlEntry[allEntries.size()]);
    }

}
