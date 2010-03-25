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

import org.apache.jackrabbit.api.security.principal.PrincipalManager;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ResourceNotFoundException;
import org.apache.sling.api.servlets.HtmlResponse;
import org.apache.sling.jcr.base.util.AccessControlUtil;
import org.apache.sling.servlets.post.Modification;

import java.security.Principal;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.jcr.Item;
import javax.jcr.RepositoryException;
import javax.jcr.Session;

/**
 * <p>
 * Sling Post Servlet implementation for modifying the ACEs for a principal on a JCR
 * resource.
 * </p>
 * <h2>Rest Service Description</h2>
 * <p>
 * Modify a principal's ACEs for the node identified as a resource by the request
 * URL &gt;resource&lt;.modifyAce.html
 * </p>
 * <h4>Methods</h4>
 * <ul>
 * <li>POST</li>
 * </ul>
 * <h4>Post Parameters</h4>
 * <dl>
 * <dt>principalId</dt>
 * <dd>The principal of the ACEs to modify in the ACL specified by the path.</dd>
 * <dt>privilege@*</dt>
 * <dd>One or more privileges, either granted or denied or none, which will be applied
 * to (or removed from) the node ACL. Any permissions that are present in an
 * existing ACE for the principal but not in the request are left untouched.</dd>
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
 *
 * @scr.component immediate="true"
 * @scr.service interface="javax.servlet.Servlet"
 * @scr.property name="sling.servlet.resourceTypes" value="sling/servlet/default"
 * @scr.property name="sling.servlet.methods" value="POST"
 * @scr.property name="sling.servlet.selectors" value="modifyAce"
 */
public class ModifyAceServlet extends AbstractAccessPostServlet {
	private static final long serialVersionUID = -9182485466670280437L;

	/* (non-Javadoc)
	 * @see org.apache.sling.jackrabbit.accessmanager.post.AbstractAccessPostServlet#handleOperation(org.apache.sling.api.SlingHttpServletRequest, org.apache.sling.api.servlets.HtmlResponse, java.util.List)
	 */
	@Override
	protected void handleOperation(SlingHttpServletRequest request,
			HtmlResponse htmlResponse, List<Modification> changes)
			throws RepositoryException {
		Session session = request.getResourceResolver().adaptTo(Session.class);
		if (session == null) {
			throw new RepositoryException("JCR Session not found");
		}

		String principalId = request.getParameter("principalId");
		if (principalId == null) {
			throw new RepositoryException("principalId was not submitted.");
		}
		PrincipalManager principalManager = AccessControlUtil.getPrincipalManager(session);
		Principal principal = principalManager.getPrincipal(principalId);
		String resourcePath = null;
		Resource resource = request.getResource();
		if (resource == null) {
			throw new ResourceNotFoundException("Resource not found.");
		} else {
			Item item = resource.adaptTo(Item.class);
			if (item != null) {
				resourcePath = item.getPath();
			} else {
				throw new ResourceNotFoundException("Resource is not a JCR Node");
			}
		}
    
		// Collect the modified privileges from the request.
		Set<String> grantedPrivilegeNames = new HashSet<String>();
		Set<String> deniedPrivilegeNames = new HashSet<String>();
		Set<String> removedPrivilegeNames = new HashSet<String>();
		Enumeration<?> parameterNames = request.getParameterNames();
		while (parameterNames.hasMoreElements()) {
			Object nextElement = parameterNames.nextElement();
			if (nextElement instanceof String) {
				String paramName = (String)nextElement;
				if (paramName.startsWith("privilege@")) {
					String privilegeName = paramName.substring(10);
					String parameterValue = request.getParameter(paramName);
					if (parameterValue != null && parameterValue.length() > 0) {
						if ("granted".equals(parameterValue)) {
							grantedPrivilegeNames.add(privilegeName);
						} else if ("denied".equals(parameterValue)) {
							deniedPrivilegeNames.add(privilegeName);
						} else if ("none".equals(parameterValue)){
							removedPrivilegeNames.add(privilegeName);
						}
					}
				}
			}
		}

		String order = request.getParameter("order");
		
		// Make the actual changes.
		try {
			AccessControlUtil.replaceAccessControlEntry(session, resourcePath, principal,
					grantedPrivilegeNames.toArray(new String[grantedPrivilegeNames.size()]),
					deniedPrivilegeNames.toArray(new String[deniedPrivilegeNames.size()]),
					removedPrivilegeNames.toArray(new String[removedPrivilegeNames.size()]),
					order);
			if (session.hasPendingChanges()) {
				session.save();
			}
		} catch (RepositoryException re) {
			throw new RepositoryException("Failed to create ace.", re);
		}
	}
}
