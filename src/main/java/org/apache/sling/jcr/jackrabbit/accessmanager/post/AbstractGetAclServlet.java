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
import java.lang.reflect.Array;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.jcr.AccessDeniedException;
import javax.jcr.Item;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.Value;
import javax.jcr.ValueFormatException;
import javax.jcr.security.AccessControlEntry;
import javax.jcr.security.Privilege;
import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.stream.JsonGenerator;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.apache.jackrabbit.api.security.JackrabbitAccessControlEntry;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.resource.ResourceNotFoundException;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.jcr.base.util.AccessControlUtil;
import org.apache.sling.jcr.jackrabbit.accessmanager.impl.PrivilegesHelper;

@SuppressWarnings("serial")
public abstract class AbstractGetAclServlet extends SlingAllMethodsServlet {

    protected static final String KEY_ORDER = "order";
	protected static final String KEY_DENIED = "denied";
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
	        response.setCharacterEncoding("UTF-8");

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

    @SuppressWarnings("unchecked")
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

		// Calculate a map of privileges to all the aggregate privileges it is contained in.
		// Use for fast lookup during the mergePrivilegeSets calls below.
        Map<Privilege, Set<Privilege>> privilegeToAncestorMap = PrivilegesHelper.buildPrivilegeToAncestorMap(jcrSession, resourcePath);

        AccessControlEntry[] declaredAccessControlEntries = getAccessControlEntries(jcrSession, resourcePath);
        Map<String, Map<String, Object>> aclMap = new LinkedHashMap<>();
        Map<String, Map<String, Object>> restrictionMap = new LinkedHashMap<>();
        int sequence = 0;

        for (AccessControlEntry ace : declaredAccessControlEntries) {
            Principal principal = ace.getPrincipal();
            Map<String, Object> map = aclMap.get(principal.getName());
            if (map == null) {
                map = new LinkedHashMap<>();
                aclMap.put(principal.getName(), map);
                map.put(KEY_ORDER, sequence++);
            }
        }
        //evaluate these in reverse order so the most entries with highest specificity are last
        for (int i = declaredAccessControlEntries.length - 1; i >= 0; i--) {
			AccessControlEntry ace = declaredAccessControlEntries[i];
			Principal principal = ace.getPrincipal();

			if (ace instanceof JackrabbitAccessControlEntry) {
				JackrabbitAccessControlEntry jace = (JackrabbitAccessControlEntry)ace;
				String[] restrictionNames = jace.getRestrictionNames();
				if (restrictionNames != null) {
					Map<String, Object> restrictions = restrictionMap.get(principal.getName());
					if (restrictions == null) {
						restrictions = new HashMap<>();
						restrictionMap.put(principal.getName(), restrictions);
					}
					for (String rname : restrictionNames) {
						try {
							//try as a single-value restriction
							Value value = jace.getRestriction(rname);
							restrictions.put(rname, value);
						} catch (ValueFormatException vfe) {
							//try as a multi-value restriction
							Value[] values = jace.getRestrictions(rname);
							restrictions.put(rname, values);
						}
					}
				}
			}
			
            Map<String, Object> map = aclMap.get(principal.getName());

            Set<Privilege> grantedSet = (Set<Privilege>) map.get(KEY_GRANTED);
            if (grantedSet == null) {
                grantedSet = new LinkedHashSet<>();
                map.put(KEY_GRANTED, grantedSet);
            }
            Set<Privilege> deniedSet = (Set<Privilege>) map.get(KEY_DENIED);
            if (deniedSet == null) {
                deniedSet = new LinkedHashSet<>();
                map.put(KEY_DENIED, deniedSet);
            }

            boolean allow = AccessControlUtil.isAllow(ace);
            if (allow) {
                Privilege[] privileges = ace.getPrivileges();
                for (Privilege privilege : privileges) {
                	PrivilegesHelper.mergePrivilegeSets(privilege,
                			privilegeToAncestorMap,
							grantedSet, deniedSet);
                }
            } else {
                Privilege[] privileges = ace.getPrivileges();
                for (Privilege privilege : privileges) {
                    PrivilegesHelper.mergePrivilegeSets(privilege,
                			privilegeToAncestorMap,
							deniedSet, grantedSet);
                }
            }
        }

        List<JsonObject> aclList = new ArrayList<>();
        Set<Entry<String, Map<String, Object>>> entrySet = aclMap.entrySet();
        for (Entry<String, Map<String, Object>> entry : entrySet) {
            String principalName = entry.getKey();
            Map<String, Object> value = entry.getValue();

            JsonObjectBuilder aceObject = Json.createObjectBuilder();
            aceObject.add("principal", principalName);

            Set<Privilege> grantedSet = (Set<Privilege>) value.get(KEY_GRANTED);
            if (grantedSet != null && !grantedSet.isEmpty()) {
                JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
                for (Privilege v : grantedSet)
                {
                    arrayBuilder.add(v.getName());
                }
                aceObject.add(KEY_GRANTED, arrayBuilder);
            }

            Set<Privilege> deniedSet = (Set<Privilege>) value.get(KEY_DENIED);
            if (deniedSet != null && !deniedSet.isEmpty()) {
                JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
                for (Privilege v : deniedSet)
                {
                    arrayBuilder.add(v.getName());
                }
                aceObject.add(KEY_DENIED, arrayBuilder);
            }
            aceObject.add(KEY_ORDER, (Integer) value.get(KEY_ORDER));

            Map<String, Object> restrictions = restrictionMap.get(principalName);
            if (restrictions != null && !restrictions.isEmpty()) {
            	Set<Entry<String, Object>> entrySet2 = restrictions.entrySet();
            	JsonObjectBuilder jsonRestrictions = Json.createObjectBuilder();
            	for (Entry<String, Object> entry2 : entrySet2) {
    				Object rvalue = entry2.getValue();
    				if (rvalue != null) {
    					if (rvalue.getClass().isArray()) {
    		                JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
    		                int length = Array.getLength(rvalue);
    		                for (int i= 0; i  < length; i++) {
    		                	Object object = Array.get(rvalue, i);
    		                	addTo(arrayBuilder, object);
    		                }
    		                jsonRestrictions.add(entry2.getKey(), arrayBuilder);
    					} else {
    						addTo(jsonRestrictions, entry2.getKey(), rvalue);
    					}
    				}
    			}
            	aceObject.add("restrictions", jsonRestrictions);
            }
            
            aclList.add(aceObject.build());
        }
        JsonObjectBuilder jsonAclMap = Json.createObjectBuilder();
        for (Map.Entry<String, Map<String, Object>> entry : aclMap.entrySet())
        {
            JsonObjectBuilder builder = Json.createObjectBuilder();
            for (Map.Entry<String, Object> inner : entry.getValue().entrySet())
            {
                addTo(builder, inner.getKey(), inner.getValue());
            }
            jsonAclMap.add(entry.getKey(), builder);
        }

        for (JsonObject jsonObj : aclList) {
            jsonAclMap.add(jsonObj.getString("principal"), jsonObj);
        }

        return jsonAclMap.build();
    }
    
    private JsonObjectBuilder addTo(JsonObjectBuilder builder, String key, Object value) {
        if (value instanceof Byte || value instanceof Short || value instanceof Integer || value instanceof Long) {
            builder.add(key, ((Number) value).longValue());
        } else if (value instanceof Float || value instanceof Double) {
            builder.add(key, ((Number) value).doubleValue());
        } else if (value instanceof Privilege) {
            JsonObjectBuilder privilegeBuilder = Json.createObjectBuilder();
            privilegeBuilder.add("name", ((Privilege) value).getName());
            builder.add(key, privilegeBuilder);
        } else if (value instanceof String) {
            builder.add(key, (String) value);
        } else {
            builder.add(key, value.toString());
        }
        return builder;
    }

    private JsonArrayBuilder addTo(JsonArrayBuilder builder, Object value) {
        if (value instanceof Byte || value instanceof Short || value instanceof Integer || value instanceof Long) {
            builder.add(((Number) value).longValue());
        } else if (value instanceof Float || value instanceof Double) {
            builder.add(((Number) value).doubleValue());
        } else if (value instanceof String) {
            builder.add((String) value);
        } else {
            builder.add(value.toString());
        }
        return builder;
    }

    protected abstract AccessControlEntry[] getAccessControlEntries(Session session, String absPath) throws RepositoryException;

}
