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
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.security.AccessControlEntry;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.AccessControlPolicy;
import javax.json.JsonObject;
import javax.servlet.Servlet;

import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.sling.jcr.jackrabbit.accessmanager.GetAcl;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicyOption;

/**
 * <p>
 * Sling GET servlet implementation for dumping the declared ACL of a resource to JSON.
 * </p>
 * <h2>Rest Service Description</h2>
 * <p>
 * Mapped to the default resourceType. Gets and Acl for a resource. Get of the form
 * &gt;resource&lt;.acl.json Provided the user has access to the ACL, they get a chunk of
 * JSON of the form.
 * </p>
 * <h3>Transport Details:</h3>
 * <h4>Methods</h4>
 * <ul>
 * <li>GET</li>
 * </ul>
 * <h4>Response</h4>
 * <dl>
 * <dt>200</dt>
 * <dd>Success.</dd>
 * <dt>404</dt>
 * <dd>The resource was not found.</dd>
 * <dt>500</dt>
 * <dd>Failure. HTML explains the failure.</dd>
 * </dl>
 * <h4>Example Response</h4>
 * <code style='white-space: pre'>
 * {
 * &quot;principalNameA&quot;:{ 
 *    &quot;permissions&quot;: {
 *      &quot;permission1&quot;:{
 *           &quot;allow&quot;:true
 *      },
 *      &quot;permission2&quot;:{
 *           &quot;allow&quot;:true
 *      },
 *      &quot;permission5&quot;:{
 *           &quot;deny&quot;:true
 *      }
 *    },
 * &quot;principalNameB&quot;:{ 
 *    &quot;permissions&quot;: {
 *      &quot;permission1&quot;:{
 *           &quot;allow&quot;:true
 *      },
 *      &quot;permission2&quot;:{
 *           &quot;allow&quot;:[
 *              "restrictionName1: "restrictionValue1",
 *              "restrictionName2: [
 *                  "restrictionValue2a",
 *                  "restrictionValue2b"
 *              ]
 *           ]
 *      },
 *      &quot;permission5&quot;:{
 *           &quot;deny&quot;:true
 *      }
 *    }
 * }
 * </code>
 */

@Component(service = {Servlet.class, GetAcl.class},
property= {
        "sling.servlet.resourceTypes=sling/servlet/default",
        "sling.servlet.methods=GET",
        "sling.servlet.selectors=acl",
        "sling.servlet.selectors=tidy.acl",
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
public class GetAclServlet extends AbstractGetAclServlet implements GetAcl {
    private static final long serialVersionUID = 3391376559396223185L;

    /* (non-Javadoc)
     * @see org.apache.sling.jcr.jackrabbit.accessmanager.GetAcl#getAcl(javax.jcr.Session, java.lang.String)
     */
    public JsonObject getAcl(Session jcrSession, String resourcePath)
            throws RepositoryException {
        return internalGetAcl(jcrSession, resourcePath);
    }

    @Override
    protected Map<String, List<AccessControlEntry>> getAccessControlEntriesMap(Session session, String absPath,
            Map<Principal, Map<DeclarationType, Set<String>>> declaredAtPaths) throws RepositoryException {
        AccessControlManager accessControlManager = session.getAccessControlManager();
        AccessControlPolicy[] policies = accessControlManager.getPolicies(absPath);
        return entriesSortedByEffectivePath(policies, ace -> true, declaredAtPaths);
    }

}
