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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.jcr.Item;
import javax.jcr.RepositoryException;
import javax.jcr.Session;

import org.apache.jackrabbit.api.jsr283.security.AccessControlEntry;
import org.apache.jackrabbit.api.jsr283.security.AccessControlList;
import org.apache.jackrabbit.api.jsr283.security.AccessControlManager;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ResourceNotFoundException;
import org.apache.sling.api.servlets.HtmlResponse;
import org.apache.sling.jcr.base.util.AccessControlUtil;
import org.apache.sling.servlets.post.Modification;
import org.apache.sling.servlets.post.SlingPostConstants;

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
 *
 * @scr.component immediate="true"
 * @scr.service interface="javax.servlet.Servlet"
 * @scr.property name="sling.servlet.resourceTypes" value="sling/servlet/default"
 * @scr.property name="sling.servlet.methods" value="POST"
 * @scr.property name="sling.servlet.selectors" value="deleteAce"
 */
public class DeleteAcesServlet extends AbstractAccessPostServlet {
	private static final long serialVersionUID = 3784866802938282971L;

	/* (non-Javadoc)
	 * @see org.apache.sling.jackrabbit.accessmanager.post.AbstractAccessPostServlet#handleOperation(org.apache.sling.api.SlingHttpServletRequest, org.apache.sling.api.servlets.HtmlResponse, java.util.List)
	 */
	@Override
	protected void handleOperation(SlingHttpServletRequest request,
			HtmlResponse htmlResponse, List<Modification> changes)
			throws RepositoryException {

        String[] applyTo = request.getParameterValues(SlingPostConstants.RP_APPLY_TO);
        if (applyTo == null) {
			throw new RepositoryException("principalIds were not sumitted.");
        } else {
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

    		Session session = request.getResourceResolver().adaptTo(Session.class);
    		if (session == null) {
    			throw new RepositoryException("JCR Session not found");
    		}

    		//load the principalIds array into a set for quick lookup below
			Set<String> pidSet = new HashSet<String>();
			pidSet.addAll(Arrays.asList(applyTo));

			try {
				AccessControlManager accessControlManager = AccessControlUtil.getAccessControlManager(session);
				AccessControlList updatedAcl = getAccessControlList(accessControlManager, resourcePath, false);

				//keep track of the existing Aces for the target principal
				AccessControlEntry[] accessControlEntries = updatedAcl.getAccessControlEntries();
				List<AccessControlEntry> oldAces = new ArrayList<AccessControlEntry>();
				for (AccessControlEntry ace : accessControlEntries) {
					if (pidSet.contains(ace.getPrincipal().getName())) {
						oldAces.add(ace);
					}
				}

				//remove the old aces
				if (!oldAces.isEmpty()) {
					for (AccessControlEntry ace : oldAces) {
						updatedAcl.removeAccessControlEntry(ace);
					}
				}

				//apply the changed policy
				accessControlManager.setPolicy(resourcePath, updatedAcl);
			} catch (RepositoryException re) {
				throw new RepositoryException("Failed to delete access control.", re);
			}
        }
	}

}
