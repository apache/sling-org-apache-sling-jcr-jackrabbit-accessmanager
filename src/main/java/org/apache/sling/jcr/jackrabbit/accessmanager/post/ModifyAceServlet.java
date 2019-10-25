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
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.jcr.Item;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.Value;
import javax.jcr.ValueFactory;
import javax.servlet.Servlet;

import org.apache.jackrabbit.api.security.principal.PrincipalManager;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionDefinition;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.resource.ResourceNotFoundException;
import org.apache.sling.jcr.base.util.AccessControlUtil;
import org.apache.sling.jcr.jackrabbit.accessmanager.ModifyAce;
import org.apache.sling.servlets.post.Modification;
import org.apache.sling.servlets.post.PostResponse;
import org.apache.sling.servlets.post.PostResponseCreator;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.component.annotations.ReferencePolicyOption;

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
 * <dt>restriction@*</dt>
 * <dd>One or more restrictions which will be applied to the ACE</dd>
 * </dl>
 * <dt>restriction@*@Delete</dt>
 * <dd>One or more restrictions which will be removed from the ACE</dd>
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

@Component(service = {Servlet.class, ModifyAce.class},
property= {
		"sling.servlet.resourceTypes=sling/servlet/default",
		"sling.servlet.methods=POST",
		"sling.servlet.selectors=modifyAce"
})
public class ModifyAceServlet extends AbstractAccessPostServlet implements ModifyAce {
	private static final long serialVersionUID = -9182485466670280437L;

	private RestrictionProvider restrictionProvider = null;

	// NOTE: the @Reference annotation is not inherited, so subclasses will need to override the #bindRestrictionProvider 
	// and #unbindRestrictionProvider methods to provide the @Reference annotation.     
	//
    @Reference(cardinality=ReferenceCardinality.OPTIONAL, policy = ReferencePolicy.DYNAMIC, policyOption=ReferencePolicyOption.GREEDY)
    protected void bindRestrictionProvider(RestrictionProvider rp) {
    	this.restrictionProvider = rp;
    }
    protected void unbindRestrictionProvider(RestrictionProvider rp) {
    	this.restrictionProvider = null;
    }
    
    /**
     * Overridden since the @Reference annotation is not inherited from the super method
     *  
	 * @see org.apache.sling.jackrabbit.usermanager.impl.post.AbstractPostServlet#bindPostResponseCreator(org.apache.sling.servlets.post.PostResponseCreator, java.util.Map)
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
	protected void unbindPostResponseCreator(PostResponseCreator creator, Map<String, Object> properties) {
		super.unbindPostResponseCreator(creator, properties);
	}
    
	
	/* (non-Javadoc)
	 * @see org.apache.sling.jackrabbit.accessmanager.post.AbstractAccessPostServlet#handleOperation(org.apache.sling.api.SlingHttpServletRequest, org.apache.sling.servlets.post.PostResponse, java.util.List)
	 */
	@Override
	protected void handleOperation(SlingHttpServletRequest request,
			PostResponse response, List<Modification> changes)
			throws RepositoryException {
		Session session = request.getResourceResolver().adaptTo(Session.class);
    	String resourcePath = request.getResource().getPath();
		String principalId = request.getParameter("principalId");
		Map<String, String> privileges = new HashMap<>();
		Map<String, Value> restrictions = new HashMap<>();
		Map<String, Value[]> mvRestrictions = new HashMap<>();
		Set<String> removeRestrictionNames = new HashSet<>();

		//lazy initialized map for quick lookup when processing POSTed restrictions
		Map<String, RestrictionDefinition> supportedRestrictionsMap = null;
		ValueFactory factory = session.getValueFactory();

		Enumeration<?> parameterNames = request.getParameterNames();
		while (parameterNames.hasMoreElements()) {
			Object nextElement = parameterNames.nextElement();
			if (nextElement instanceof String) {
				String paramName = (String)nextElement;
				if (paramName.startsWith("privilege@")) {
					String privilegeName = paramName.substring(10);
					String parameterValue = request.getParameter(paramName);
					privileges.put(privilegeName, parameterValue);
				} else if (paramName.startsWith("restriction@")) {
					if (restrictionProvider == null) {
						throw new IllegalArgumentException("No restriction provider is available so unable to process POSTed restriction values");
					}
					if (supportedRestrictionsMap == null) {
						supportedRestrictionsMap = new HashMap<>();

						//populate the map for quick lookup below
						Set<RestrictionDefinition> supportedRestrictions = restrictionProvider.getSupportedRestrictions(resourcePath);
						for (RestrictionDefinition restrictionDefinition : supportedRestrictions) {
							supportedRestrictionsMap.put(restrictionDefinition.getName(), restrictionDefinition);
						}
					}
					
					if (paramName.endsWith("@Delete")) {
						String restrictionName = paramName.substring(12, paramName.length() - 7);
						removeRestrictionNames.add(restrictionName);
					} else {
						String restrictionName = paramName.substring(12);
						String[] parameterValues = request.getParameterValues(paramName);
						if (parameterValues != null) {
							RestrictionDefinition rd = supportedRestrictionsMap.get(restrictionName);
							if (rd == null) {
								//illegal restriction name?
								throw new IllegalArgumentException("Invalid or not supported restriction name was supplied");
							}
							
							boolean multival = rd.getRequiredType().isArray();
							int restrictionType = rd.getRequiredType().tag();
							
							if (multival) {
								Value [] v = new Value[parameterValues.length];
								for (int j = 0; j < parameterValues.length; j++) {
									String string = parameterValues[j];
									v[j] = factory.createValue(string, restrictionType);
								}

								mvRestrictions.put(restrictionName, v);
							} else if (parameterValues.length > 0) {
								Value v = factory.createValue(parameterValues[0], restrictionType);
								restrictions.put(restrictionName, v);
							}
						}
					}
				}
			}
		}
		String order = request.getParameter("order");
    	modifyAce(session, resourcePath, principalId, privileges, order, restrictions, mvRestrictions, 
    			removeRestrictionNames, false);
	}
	

	/* (non-Javadoc)
	 * @see org.apache.sling.jcr.jackrabbit.accessmanager.ModifyAce#modifyAce(javax.jcr.Session, java.lang.String, java.lang.String, java.util.Map, java.lang.String, boolean)
	 */
	@Override
	public void modifyAce(Session jcrSession, String resourcePath, String principalId, Map<String, String> privileges,
			String order, boolean autoSave) throws RepositoryException {
		modifyAce(jcrSession, resourcePath, principalId, privileges, order, 
				null, null, null, autoSave);
	}

	/* (non-Javadoc)
	 * @see org.apache.sling.jcr.jackrabbit.accessmanager.ModifyAce#modifyAce(javax.jcr.Session, java.lang.String, java.lang.String, java.util.Map, java.lang.String)
	 */
	public void modifyAce(Session jcrSession, String resourcePath,
			String principalId, Map<String, String> privileges, String order)
			throws RepositoryException {
		modifyAce(jcrSession, resourcePath, principalId, privileges, order, true);
	}
	/* (non-Javadoc)
	 * @see org.apache.sling.jcr.jackrabbit.accessmanager.ModifyAce#modifyAce(javax.jcr.Session, java.lang.String, java.lang.String, java.util.Map, java.lang.String, java.util.Map, java.util.Map, java.util.Set)
	 */
	@Override
	public void modifyAce(Session jcrSession, String resourcePath, String principalId, Map<String, String> privileges,
			String order, Map<String, Value> restrictions, Map<String, Value[]> mvRestrictions,
			Set<String> removeRestrictionNames) throws RepositoryException {
		modifyAce(jcrSession, resourcePath, principalId, privileges, order, 
				restrictions, mvRestrictions, removeRestrictionNames, true);
	}	
	
	/* (non-Javadoc)
	 * @see org.apache.sling.jcr.jackrabbit.accessmanager.ModifyAce#modifyAce(javax.jcr.Session, java.lang.String, java.lang.String, java.util.Map, java.lang.String, java.util.Map, java.util.Map, java.util.Set, boolean)
	 */
	@Override
	public void modifyAce(Session jcrSession, String resourcePath, String principalId, Map<String, String> privileges,
			String order, Map<String, Value> restrictions, Map<String, Value[]> mvRestrictions,
			Set<String> removeRestrictionNames, boolean autoSave) throws RepositoryException {
		if (jcrSession == null) {
			throw new RepositoryException("JCR Session not found");
		}

		if (principalId == null) {
			throw new RepositoryException("principalId was not submitted.");
		}
		PrincipalManager principalManager = AccessControlUtil.getPrincipalManager(jcrSession);
		Principal principal = principalManager.getPrincipal(principalId);
		
    	if (resourcePath == null) {
			throw new ResourceNotFoundException("Resource path was not supplied.");
    	}

		Item item = jcrSession.getItem(resourcePath);
		if (item != null) {
			resourcePath = item.getPath();
		} else {
			throw new ResourceNotFoundException("Resource is not a JCR Node");
		}
		
		// Collect the modified privileges from the request.
		Set<String> grantedPrivilegeNames = new HashSet<String>();
		Set<String> deniedPrivilegeNames = new HashSet<String>();
		Set<String> removedPrivilegeNames = new HashSet<String>();
		if (privileges != null) {
			Set<Entry<String, String>> entrySet = privileges.entrySet();
			for (Entry<String, String> entry : entrySet) {
				String privilegeName = entry.getKey();
				if (privilegeName.startsWith("privilege@")) {
					privilegeName = privilegeName.substring(10);
				}
				String parameterValue = entry.getValue();
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

		// Make the actual changes.
		try {
			AccessControlUtil.replaceAccessControlEntry(jcrSession, resourcePath, principal,
					grantedPrivilegeNames.toArray(new String[grantedPrivilegeNames.size()]),
					deniedPrivilegeNames.toArray(new String[deniedPrivilegeNames.size()]),
					removedPrivilegeNames.toArray(new String[removedPrivilegeNames.size()]),
					order,
					restrictions,
					mvRestrictions,
					removeRestrictionNames);
			if (autoSave && jcrSession.hasPendingChanges()) {
				jcrSession.save();
			}
		} catch (RepositoryException re) {
			throw new RepositoryException("Failed to create ace.", re);
		}
	}
	
}
