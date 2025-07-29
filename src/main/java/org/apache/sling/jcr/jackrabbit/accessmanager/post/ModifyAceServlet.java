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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.UnsupportedRepositoryOperationException;
import javax.jcr.Value;
import javax.jcr.ValueFactory;
import javax.jcr.security.AccessControlEntry;
import javax.jcr.security.AccessControlException;
import javax.jcr.security.AccessControlList;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.AccessControlPolicy;
import javax.jcr.security.AccessControlPolicyIterator;
import javax.jcr.security.Privilege;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlEntry;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlList;
import org.apache.jackrabbit.api.security.authorization.PrincipalAccessControlList;
import org.apache.jackrabbit.api.security.principal.PrincipalManager;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionDefinition;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.sling.api.SlingJakartaHttpServletRequest;
import org.apache.sling.jcr.jackrabbit.accessmanager.LocalPrivilege;
import org.apache.sling.jcr.jackrabbit.accessmanager.LocalRestriction;
import org.apache.sling.jcr.jackrabbit.accessmanager.ModifyAce;
import org.apache.sling.jcr.jackrabbit.accessmanager.impl.PrivilegesHelper;
import org.apache.sling.servlets.post.JakartaPostResponse;
import org.apache.sling.servlets.post.JakartaPostResponseCreator;
import org.apache.sling.servlets.post.Modification;
import org.apache.sling.servlets.post.SlingPostConstants;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicyOption;

import jakarta.servlet.Servlet;

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
 * existing ACE for the principal but not in the request are left untouched. The parameter value must be either 'allow', 'deny' or 'all'. 
 * For backward compatibility, 'granted' or 'denied' may also be used for the parameter value as an alias for 'allow' or 'deny'.</dd>
 * <dt>restriction@[restriction_name]</dt>
 * <dd>One or more restrictions which will be applied to the ACE. The value is the target value of the restriction to be set.</dd>
 * <dt>restriction@[restriction_name]@Delete</dt>
 * <dd>One or more restrictions which will be removed from the ACE</dd>
 * <dt>privilege@[privilege_name]@Delete</dt>
 * <dd>One param for each privilege to delete. The parameter value must be either 'allow', 'deny' or 'all' to specify which state to delete from</dd>
 * <dt>restriction@[privilege_name]@[restriction_name]@Allow</dt>
 * <dt>restriction@[privilege_name]@[restriction_name]@Deny</dt>
 * <dd>One param for each restriction value. The same parameter name may be used again for multi-value restrictions. The @Allow or @Deny suffix 
 *     specifies whether to apply the restriction to the 'allow' or 'deny' privilege.  The value is the target value of the restriction to be set.</dd>
 * <dt>restriction@[privilege_name]@[restriction_name]@Delete</dt>
 * <dd>One param for each restriction to delete. The parameter value must be either 'allow', 'deny' or 'all' to specify which state to delete from.</dd>
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
        "sling.servlet.selectors=modifyAce",
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
public class ModifyAceServlet extends AbstractAccessPostServlet implements ModifyAce {
    private static final long serialVersionUID = -9182485466670280437L;
    private static final String INVALID_OR_NOT_SUPPORTED_RESTRICTION_NAME_WAS_SUPPLIED = "Invalid restriction name was supplied";

    /**
     * Possible values for a privilege parameter
     */
    private enum PrivilegeValues {
            ALLOW("allow"),
            GRANTED("granted"),
            NONE("none"),
            DENIED("denied"),
            DENY("deny"),
            INVALID("*");

        private String paramValue;

        private PrivilegeValues(String paramValue) {
            this.paramValue = paramValue;
        }

        public String getParamValue() {
            return paramValue;
        }

        public static PrivilegeValues valueOfParam(String value) {
            return Stream.of(PrivilegeValues.values())
                .filter(item -> item.paramValue.equalsIgnoreCase(value))
                .findFirst()
                .orElse(INVALID);
        }
    }

    /**
     * Possible values for a delete privilege or restriction parameter
     */
    private enum DeleteValues {
        ALL("all"),
        ALLOW("allow"),
        DENY("deny"),
        INVALID("*");

        private String paramValue;

        private DeleteValues(String paramValue) {
            this.paramValue = paramValue;
        }

        public static DeleteValues valueOfParam(String value) {
            return Stream.of(DeleteValues.values())
                .filter(item -> item.paramValue.equalsIgnoreCase(value))
                .findFirst()
                .orElse(INVALID);
        }
    }

    private static final Pattern PRIVILEGE_PATTERN = Pattern.compile(String.format("^privilege@(.+)(?<!%s)$",
            SlingPostConstants.SUFFIX_DELETE));
    private static final Pattern PRIVILEGE_PATTERN_DELETE = Pattern.compile(String.format("^privilege@(.+)%s$",
            SlingPostConstants.SUFFIX_DELETE));
    private static final Pattern RESTRICTION_PATTERN = Pattern.compile("^restriction@([^@]+)(@([^@]+)@(Allow|Deny))?$");
    private static final Pattern RESTRICTION_PATTERN_DELETE = Pattern.compile(String.format("^restriction@([^@]+)(@([^@]+))?%s$",
                SlingPostConstants.SUFFIX_DELETE));

    /* (non-Javadoc)
     * @see org.apache.sling.jackrabbit.accessmanager.post.AbstractAccessPostServlet#handleOperation(org.apache.sling.api.SlingJakartaHttpServletRequest, org.apache.sling.servlets.post.JakartaPostResponse, java.util.List)
     */
    @Override
    protected void handleOperation(SlingJakartaHttpServletRequest request,
            JakartaPostResponse response, List<Modification> changes)
            throws RepositoryException {
        Session session = request.getResourceResolver().adaptTo(Session.class);
        String resourcePath = getItemPath(request);
        String principalId = request.getParameter("principalId");
        String order = request.getParameter("order");

        Principal principal = validateArgs(session, resourcePath, principalId);

        // Calculate a map of restriction names to the restriction definition.
        // Use for fast lookup during the calls below.
        Map<String, RestrictionDefinition> srMap = buildRestrictionNameToDefinitionMap(resourcePath);
        AccessControlManager acm = session.getAccessControlManager();
        Map<Privilege, Integer> privilegeLongestDepthMap = PrivilegesHelper.buildPrivilegeLongestDepthMap(acm.privilegeFromName(PrivilegeConstants.JCR_ALL));

        // first calculate what is currently stored in the ace
        Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap = loadStoredAce(acm, resourcePath, principal, srMap);

        // and now merge the changes from the request parameters
        processPostedPrivilegeDeleteParams(acm, request, privilegeToLocalPrivilegesMap);
        processPostedRestrictionDeleteParams(acm, request, srMap, privilegeToLocalPrivilegesMap);
        processPostedPrivilegeAndRestrictionParams(acm, request, srMap, privilegeToLocalPrivilegesMap, privilegeLongestDepthMap);

        // consolidate any aggregates that are still valid
        PrivilegesHelper.consolidateAggregates(session, resourcePath, privilegeToLocalPrivilegesMap, privilegeLongestDepthMap);

        // and then store it
        modifyAce(session, resourcePath, principalId, privilegeToLocalPrivilegesMap.values(), order, false, changes);
    }

    /**
     * Verify that the user supplied arguments are valid
     * 
     * @param jcrSession the JCR session
     * @param resourcePath the resource path
     * @param principalId the principal id
     * @return the principal for the requested principalId
     */
    protected @NotNull Principal validateArgs(Session jcrSession, String resourcePath, String principalId) throws RepositoryException {
        if (jcrSession == null) {
            throw new RepositoryException("JCR Session not found");
        }

        if (RestrictionProvider.EMPTY.equals(getRestrictionProvider())) {
            throw new IllegalStateException("No restriction provider is available so unable to process POSTed restriction values");
        }

        if (principalId == null) {
            throw new RepositoryException("principalId was not submitted.");
        }

        // validate that the submitted name is valid
        PrincipalManager principalManager = ((JackrabbitSession)jcrSession).getPrincipalManager();
        Principal principal = principalManager.getPrincipal(principalId);
        if (principal == null) {
            throw new RepositoryException("Invalid principalId was submitted.");
        }

        validateResourcePath(jcrSession, resourcePath);

        AccessControlManager acm = jcrSession.getAccessControlManager();
        JackrabbitAccessControlList acl = getAcl(acm, resourcePath, principal);
        if (acl == null) {
            throw new IllegalStateException("No access control list is available so unable to process");
        }

        return principal;
    }

    /**
     * Calculate a map of restriction names to the restriction definition
     * 
     * @param resourcePath the path of the resource
     * @return map of restriction names to definition
     */
    protected @NotNull Map<String, RestrictionDefinition> buildRestrictionNameToDefinitionMap(@NotNull String resourcePath) {
        Set<RestrictionDefinition> supportedRestrictions = getRestrictionProvider().getSupportedRestrictions(resourcePath);
        Map<String, RestrictionDefinition> srMap = new HashMap<>();
        for (RestrictionDefinition restrictionDefinition : supportedRestrictions) {
            srMap.put(restrictionDefinition.getName(), restrictionDefinition);
        }
        return srMap;
    }

    /**
     * Loads the state for the currently stored ACE for the specified principal.
     * The state for any aggregate privilege is expanded to make it easier to merge changes.
     * 
     * @param acm the access control manager
     * @param resourcePath the resource path
     * @param forPrincipal the principal to load the ace for
     * @param srMap map of restriction names to the restriction definition
     * @return the privileges from the ace as a map where the key is the privilege
     *          and the value is the LocalPrivilege that encapsulates the state
     */
    protected @NotNull Map<Privilege, LocalPrivilege> loadStoredAce(@NotNull AccessControlManager acm, @NotNull String resourcePath,
            @NotNull Principal forPrincipal, @NotNull Map<String, RestrictionDefinition> srMap) throws RepositoryException {
        Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap = new HashMap<>();
        JackrabbitAccessControlList acl = getAcl(acm, resourcePath, forPrincipal);
        AccessControlEntry[] accessControlEntries = acl.getAccessControlEntries();
        for (AccessControlEntry accessControlEntry : accessControlEntries) {
            JackrabbitAccessControlEntry jrAccessControlEntry = getJackrabbitAccessControlEntry(accessControlEntry, resourcePath, forPrincipal);
            if (jrAccessControlEntry != null) {
                Privilege[] privileges = jrAccessControlEntry.getPrivileges();
                if (privileges != null) {
                    boolean isAllow = jrAccessControlEntry.isAllow();
                    // populate the declared restrictions
                    @NotNull
                    String[] restrictionNames = jrAccessControlEntry.getRestrictionNames();
                    Set<LocalRestriction> restrictionItems = new HashSet<>();
                    for (String restrictionName : restrictionNames) {
                        RestrictionDefinition rd = srMap.get(restrictionName);
                        if (rd != null) { // should never get null value here
                            boolean isMulti = rd.getRequiredType().isArray();
                            if (isMulti) {
                                restrictionItems.add(new LocalRestriction(rd, jrAccessControlEntry.getRestrictions(restrictionName)));
                            } else {
                                restrictionItems.add(new LocalRestriction(rd, jrAccessControlEntry.getRestriction(restrictionName)));
                            }
                        }
                    }

                    if (isAllow) {
                        PrivilegesHelper.allow(privilegeToLocalPrivilegesMap, restrictionItems, Arrays.asList(privileges));
                    } else {
                        PrivilegesHelper.deny(privilegeToLocalPrivilegesMap, restrictionItems, Arrays.asList(privileges));
                    }
                }
            }
        }
        return privilegeToLocalPrivilegesMap;
    }

    protected @Nullable JackrabbitAccessControlEntry getJackrabbitAccessControlEntry(@NotNull AccessControlEntry entry, @NotNull String resourcePath,
            @NotNull Principal forPrincipal) {
        JackrabbitAccessControlEntry jrEntry = null;
        if (entry instanceof JackrabbitAccessControlEntry &&
                entry.getPrincipal().equals(forPrincipal)) {
            jrEntry = (JackrabbitAccessControlEntry)entry;
        }
        return jrEntry;
    }

    /**
     * Helper to return a filtered list of parameter names that match the pattern
     * @param request the current request
     * @param pattern the regex pattern to match
     * @return map of parameter names to Matcher that match the pattern
     */
    protected @NotNull Map<String, Matcher> getMatchedRequestParameterNames(@NotNull SlingJakartaHttpServletRequest request, @NotNull Pattern pattern) {
        Map<String, Matcher> keys = new HashMap<>();
        Enumeration<String> parameterNames = request.getParameterNames();
        while (parameterNames.hasMoreElements()) {
            String key = parameterNames.nextElement();
            Matcher matcher = pattern.matcher(key);
            if (matcher.matches()) {
                keys.put(key, matcher);
            }
        }
        return keys;
    }

    /**
     * Merge into the privilegeToLocalPrivilegesMap the changes requested in privilege
     * delete request parameters.
     * 
     * @param acm the access control manager
     * @param request the current request
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     */
    protected void processPostedPrivilegeDeleteParams(@NotNull AccessControlManager acm,
            @NotNull SlingJakartaHttpServletRequest request,
            @NotNull Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap) throws RepositoryException {
        @NotNull
        Map<String, Matcher> postedPrivilegeDeleteNames = getMatchedRequestParameterNames(request, PRIVILEGE_PATTERN_DELETE);
        for (Entry<String, Matcher> entry : postedPrivilegeDeleteNames.entrySet()) {
            String paramName = entry.getKey();
            Matcher matcher = entry.getValue();
            String privilegeName = matcher.group(1);
            Privilege privilege = acm.privilegeFromName(privilegeName);
            String paramValue = request.getParameter(paramName);
            DeleteValues value = DeleteValues.valueOfParam(paramValue);
            if (DeleteValues.ALL.equals(value) || DeleteValues.ALLOW.equals(value)) {
                PrivilegesHelper.unallow(privilegeToLocalPrivilegesMap,
                        Collections.singleton(privilege));
            }
            if (DeleteValues.ALL.equals(value) || DeleteValues.DENY.equals(value)) {
                PrivilegesHelper.undeny(privilegeToLocalPrivilegesMap,
                        Collections.singleton(privilege));
            }
        }
    }

    /**
     * Merge into the privilegeToLocalPrivilegesMap the changes requested in restriction
     * delete request parameters.
     * 
     * @param acm the access control manager
     * @param request the current request
     * @param srMap map of restriction names to the restriction definition
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     */
    protected void processPostedRestrictionDeleteParams(@NotNull AccessControlManager acm,
            @NotNull SlingJakartaHttpServletRequest request,
            @NotNull Map<String, RestrictionDefinition> srMap,
            @NotNull Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap) throws RepositoryException {
        @NotNull
        Map<String, Matcher> postedRestrictionDeleteNames = getMatchedRequestParameterNames(request, RESTRICTION_PATTERN_DELETE);
        for (Entry<String, Matcher> entry : postedRestrictionDeleteNames.entrySet()) {
            String paramName = entry.getKey();
            Matcher matcher = entry.getValue();
            String privilegeName;
            String restrictionName;
            if (matcher.group(2) != null) {
                privilegeName = matcher.group(1);
                restrictionName = matcher.group(3);
            } else {
                privilegeName = null;
                restrictionName = matcher.group(1);
            }
            RestrictionDefinition rd = srMap.get(restrictionName);
            if (rd == null) {
                //illegal restriction name?
                throw new AccessControlException(INVALID_OR_NOT_SUPPORTED_RESTRICTION_NAME_WAS_SUPPLIED);
            }
            Collection<Privilege> privileges;
            if (privilegeName == null) {
                // process for every privilege
                privileges = privilegeToLocalPrivilegesMap.keySet();
            } else {
                // process for the specific privilege only
                Privilege privilege = acm.privilegeFromName(privilegeName);
                privileges = Collections.singletonList(privilege);
            }
            String[] parameterValues;
            if (privilegeName == null) {
                // for backward compatibility, the restriction@[restriction_name]@Delete syntax
                //   deletes from both 'allow' and 'deny'
                parameterValues = new String[] { "all" };
            } else {
                parameterValues = request.getParameterValues(paramName);
            }
            for (String allowOrDeny : parameterValues) {
                DeleteValues value = DeleteValues.valueOfParam(allowOrDeny);
                switch (value) {
                case ALL:
                    // not specified try both the deny and allow sets
                    PrivilegesHelper.unallowOrUndenyRestriction(privilegeToLocalPrivilegesMap,
                            restrictionName, privileges);
                    break;
                case ALLOW:
                    PrivilegesHelper.unallowRestriction(privilegeToLocalPrivilegesMap,
                            restrictionName, privileges);
                    break;
                case DENY:
                    PrivilegesHelper.undenyRestriction(privilegeToLocalPrivilegesMap,
                            restrictionName, privileges);
                    break;
                default:
                    break;
                }
            }
        }
    }

    /**
     * Populate the restrictions that that were posted and applicable
     * to the requested privilege
     * 
     * @param request the current request
     * @param srMap map of restriction names to the restriction definition
     * @param forPrivilege the privilege to load the restrictions for
     * @param forAllowOrDeny either {@link PrivilegeValues#ALLOW} or {@link PrivilegeValues#DENY}
     * @param generalRestrictions the general restrictions that are not for a specific privilege
     */
    protected Set<LocalRestriction> postedRestrictionsForPrivilege(
            @NotNull SlingJakartaHttpServletRequest request,
            @NotNull Map<String, RestrictionDefinition> srMap,
            @NotNull Privilege forPrivilege,
            @NotNull PrivilegeValues forAllowOrDeny,
            @NotNull Set<LocalRestriction> generalRestrictions) throws RepositoryException {
        Set<LocalRestriction> restrictions = new HashSet<>(generalRestrictions);

        @NotNull
        Map<String, Matcher> postedRestrictionParams = getMatchedRequestParameterNames(request, RESTRICTION_PATTERN);
        for (Entry<String, Matcher> entry : postedRestrictionParams.entrySet()) {
            String paramName = entry.getKey();
            Matcher matcher = entry.getValue();
            String privilegeName;
            String restrictionName;
            PrivilegeValues allowOrDeny;
            if (matcher.group(2) != null) {
                privilegeName = matcher.group(1);
                restrictionName = matcher.group(3);
                allowOrDeny = PrivilegeValues.valueOfParam(matcher.group(4));
            } else {
                privilegeName = null;
                restrictionName = matcher.group(1);
                allowOrDeny = null;
            }

            if ((privilegeName == null || forPrivilege.getName().equals(privilegeName)) &&
                    (allowOrDeny == null || forAllowOrDeny.equals(allowOrDeny))) {
                LocalRestriction localRestriction = toLocalRestriction(request, srMap, restrictionName, paramName);
                restrictions.removeIf(r -> r.getName().equals(localRestriction.getName()));
                restrictions.add(localRestriction);
            }
        }

        return restrictions;
    }

    /**
     * Construct a LocalRestriction using data a request parameter
     * 
     * @param request the current request
     * @param srMap map of restriction names to the restriction definition
     * @param restrictionName the name of the restriction
     * @param paramName the request parameter name that contains the restriction values
     */
    protected LocalRestriction toLocalRestriction(
            @NotNull SlingJakartaHttpServletRequest request,
            @NotNull Map<String, RestrictionDefinition> srMap,
            @NotNull String restrictionName,
            @NotNull String paramName) throws RepositoryException {
        RestrictionDefinition rd = srMap.get(restrictionName);
        if (rd == null) {
            //illegal restriction name?
            throw new AccessControlException(INVALID_OR_NOT_SUPPORTED_RESTRICTION_NAME_WAS_SUPPLIED);
        }
        Session session = request.getResourceResolver().adaptTo(Session.class);
        ValueFactory vf = session.getValueFactory();
        LocalRestriction localRestriction;
        int restrictionType = rd.getRequiredType().tag();
        if (rd.getRequiredType().isArray()) {
            // multi-value
            String[] parameterValues = request.getParameterValues(paramName);
            Value[] restrictionValue = new Value[parameterValues.length];
            for (int i = 0; i < parameterValues.length; i++) {
                restrictionValue[i] = vf.createValue(parameterValues[i], restrictionType);
            }
            localRestriction = new LocalRestriction(rd, restrictionValue);
        } else {
            // single value
            Value restrictionValue = vf.createValue(request.getParameter(paramName), restrictionType);
            localRestriction = new LocalRestriction(rd, restrictionValue);
        }
        return localRestriction;
    }

    /**
     * Merge into the privilegeToLocalPrivilegesMap the changes requested in privilege and
     * restriction request parameters.
     * 
     * @param acm the access control manager
     * @param request the current request
     * @param srMap map of restriction names to the restriction definition
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param privilegeLongestDepthMap the map of privileges to their longest depth
     */
    protected void processPostedPrivilegeAndRestrictionParams(@NotNull AccessControlManager acm,
            @NotNull SlingJakartaHttpServletRequest request,
            @NotNull Map<String, RestrictionDefinition> srMap,
            @NotNull Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap,
            @NotNull Map<Privilege, Integer> privilegeLongestDepthMap) throws RepositoryException {
        @NotNull
        Map<String, Matcher> postedPrivilegeNameKeys = getMatchedRequestParameterNames(request, PRIVILEGE_PATTERN);

        // collect all the privileges so we can process them in the right order
        Map<Privilege, Set<String>> privilegeToParamValuesMap = new HashMap<>();
        for (Entry<String, Matcher> entry : postedPrivilegeNameKeys.entrySet()) {
            String paramName = entry.getKey();
            Matcher matcher = entry.getValue();
            String privilegeName = matcher.group(1);
            Privilege privilege = acm.privilegeFromName(privilegeName);
            Set<String> paramValues = privilegeToParamValuesMap.computeIfAbsent(privilege, p -> new HashSet<>());
            paramValues.addAll(Arrays.asList(request.getParameterValues(paramName)));
        }

        //also check for any restriction params
        Set<LocalRestriction> generalRestrictions = new HashSet<>();
        Map<String, Matcher> postedRestrictionParams = getMatchedRequestParameterNames(request, RESTRICTION_PATTERN);
        for (Entry<String, Matcher> entry : postedRestrictionParams.entrySet()) {
            Matcher matcher = entry.getValue();
            if (matcher.group(2) != null) {
                PrivilegeValues allowOrDeny = PrivilegeValues.valueOfParam(matcher.group(4));
                if (PrivilegeValues.ALLOW.equals(allowOrDeny) ||
                        PrivilegeValues.DENY.equals(allowOrDeny)) {
                    String privilegeName = matcher.group(1);
                    Privilege privilege = acm.privilegeFromName(privilegeName);
                    Set<String> paramValues = privilegeToParamValuesMap.computeIfAbsent(privilege, p -> new HashSet<>());
                    paramValues.add(allowOrDeny.getParamValue());
                }
            } else {
                // restriction but not for a specific privilege
                String restrictionName = matcher.group(1);
                String paramName = entry.getKey();
                LocalRestriction localRestriction = toLocalRestriction(request, srMap, restrictionName, paramName);
                generalRestrictions.removeIf(r -> r.getName().equals(localRestriction.getName()));
                generalRestrictions.add(localRestriction);
            }
        }

        // apply the general restrictions to any already existing privilege that was not posted
        //   with new state
        if (!generalRestrictions.isEmpty()) {
            for (Entry<Privilege, LocalPrivilege> entry : privilegeToLocalPrivilegesMap.entrySet()) {
                Privilege p = entry.getKey();
                if (!privilegeToParamValuesMap.containsKey(p)) {
                    LocalPrivilege lp = entry.getValue();
                    applyPrivilegeAndRestrictions(privilegeToLocalPrivilegesMap, p, 
                            lp.isAllow(), generalRestrictions, 
                            lp.isDeny(), generalRestrictions);
                }
            }
        }

        List<Entry<Privilege, Set<String>>> sortedEntries = new ArrayList<>(privilegeToParamValuesMap.entrySet());
        // sort the entries to process the most shallow last
        Collections.sort(sortedEntries, (e1, e2) -> privilegeLongestDepthMap.get(e1.getKey()).compareTo(privilegeLongestDepthMap.get(e2.getKey())));
        for (Entry<Privilege, Set<String>> entry : sortedEntries) {
            Set<String> paramValues = entry.getValue();
            Privilege privilege = entry.getKey();

            // convert and sort the values to ensure that allow goes after
            //  deny or none when there is a conflict
            List<PrivilegeValues> privilegeValues = paramValues.stream()
                .map(PrivilegeValues::valueOfParam)
                .sorted((v1, v2) -> Integer.compare(v2.ordinal(), v1.ordinal()))
                .collect(Collectors.toList());
            boolean none = false;
            boolean allow = false;
            Set<LocalRestriction> allowRestrictions = Collections.emptySet();
            boolean deny = false;
            Set<LocalRestriction> denyRestrictions = Collections.emptySet();
            for (PrivilegeValues value : privilegeValues) {
                switch (value) {
                case DENY:
                case DENIED:
                    deny = true;
                    denyRestrictions = postedRestrictionsForPrivilege(request, srMap, privilege, value, generalRestrictions);
                    break;
                case ALLOW:
                case GRANTED:
                    allow = true;
                    allowRestrictions = postedRestrictionsForPrivilege(request, srMap, privilege, value, generalRestrictions);
                    break;
                case NONE:
                    none = true;
                    break;
                default:
                    break;
                }
            }
            if (none) {
                PrivilegesHelper.none(privilegeToLocalPrivilegesMap, Collections.singleton(privilege));
            }
            applyPrivilegeAndRestrictions(privilegeToLocalPrivilegesMap, privilege,
                    allow, allowRestrictions, 
                    deny, denyRestrictions);
        }
    }

    /**
     * Apply the privilege and restrictions to the local privileges
     * 
     * @param privilegeToLocalPrivilegesMap the map containing the declared LocalPrivilege items
     * @param p the privilege
     * @param allow true if the privilege is to be allowed
     * @param allowRestrictions restrictions (if any) for the allow
     * @param deny true if the privilege is to be denied
     * @param denyRestrictions restrictions (if any) for the deny
     */
    protected void applyPrivilegeAndRestrictions(
            @NotNull Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap,
            @NotNull Privilege p, 
            boolean allow, @NotNull Set<LocalRestriction> allowRestrictions,
            boolean deny, @NotNull Set<LocalRestriction> denyRestrictions) throws RepositoryException {
        if (allow) {
            // clear out the state that we are replacing
            PrivilegesHelper.unallowRestrictions(privilegeToLocalPrivilegesMap,
                    allowRestrictions.stream().map(LocalRestriction::getName).collect(Collectors.toSet()),
                    Collections.singleton(p));
        }
        if (deny) {
            // clear out the state that we are replacing
            PrivilegesHelper.undenyRestrictions(privilegeToLocalPrivilegesMap,
                    denyRestrictions.stream().map(LocalRestriction::getName).collect(Collectors.toSet()),
                    Collections.singleton(p));
        }
        if (allow && deny) {
            PrivilegesHelper.allowAndDeny(privilegeToLocalPrivilegesMap, 
                    allow, allowRestrictions, deny, denyRestrictions,
                    Collections.singleton(p));
        } else if (allow) {
            PrivilegesHelper.allow(privilegeToLocalPrivilegesMap, allowRestrictions, Collections.singleton(p));
        } else if (deny) {
            PrivilegesHelper.deny(privilegeToLocalPrivilegesMap, denyRestrictions, Collections.singleton(p));
        }
    }

    /**
     * Lookup the ACL for the given resource
     * 
     * @param acm the access control manager
     * @param resourcePath the resource path
     * @param principal the principal for principalbased ACL
     * @return the found ACL object
     */
    protected JackrabbitAccessControlList getAcl(@NotNull AccessControlManager acm, String resourcePath, Principal principal)
            throws RepositoryException {
        AccessControlPolicy[] policies = acm.getPolicies(resourcePath);
        JackrabbitAccessControlList acl = null;
        for (AccessControlPolicy policy : policies) {
            if (policy instanceof JackrabbitAccessControlList) {
                acl = (JackrabbitAccessControlList) policy;
                break;
            }
        }
        if (acl == null) {
            AccessControlPolicyIterator applicablePolicies = acm.getApplicablePolicies(resourcePath);
            while (applicablePolicies.hasNext()) {
                AccessControlPolicy policy = applicablePolicies.nextAccessControlPolicy();
                if (policy instanceof JackrabbitAccessControlList) {
                    acl = (JackrabbitAccessControlList) policy;
                    break;
                }
            }
        }
        return acl;
    }

    /**
     * Remove all of the ACEs for the specified principal from the ACL
     * 
     * @param order the requested order (may be null)
     * @param principal the principal whose aces should be removed
     * @param acl the access control list to update
     * @return the original order if it was supplied, otherwise the order of the first ACE 
     */
    protected String removeAces(@NotNull String resourcePath, @Nullable String order, @NotNull Principal principal, @NotNull JackrabbitAccessControlList acl) // NOSONAR
            throws RepositoryException {
        AccessControlEntry[] existingAccessControlEntries = acl.getAccessControlEntries();

        if (order == null || order.length() == 0) {
            //order not specified, so keep track of the original ACE position.
            Set<Principal> processedPrincipals = new HashSet<>();
            for (int j = 0; j < existingAccessControlEntries.length; j++) {
                AccessControlEntry ace = existingAccessControlEntries[j];
                Principal principal2 = ace.getPrincipal();
                if (principal2.equals(principal)) {
                    order = String.valueOf(processedPrincipals.size());
                    break;
                } else {
                    processedPrincipals.add(principal2);
                }
            }
        }

        for (int j = 0; j < existingAccessControlEntries.length; j++) {
            AccessControlEntry ace = existingAccessControlEntries[j];
            if (ace.getPrincipal().equals(principal)) {
                acl.removeAccessControlEntry(ace);
            }
        }
        return order;
    }

    /**
     * Add ACEs for the specified principal to the ACL.  One ACE is added for each unique
     * restriction set.
     * 
     * @param resourcePath the path of the resource
     * @param principal the principal whose aces should be added
     * @param restrictionsToLocalPrivilegesMap the map containing the restrictions mapped to the LocalPrivlege items with those resrictions
     * @param isAllow true for 'allow' ACE, false for 'deny' ACE
     * @param acl the access control list to update
     */
    protected void addAces(@NotNull String resourcePath, @NotNull Principal principal,
            @NotNull Map<Set<LocalRestriction>, List<LocalPrivilege>> restrictionsToLocalPrivilegesMap,
            boolean isAllow,
            @NotNull JackrabbitAccessControlList acl,
            Map<Privilege, Integer> privilegeLongestDepthMap) throws RepositoryException {

        List<Entry<Set<LocalRestriction>, List<LocalPrivilege>>> sortedEntries = new ArrayList<>(restrictionsToLocalPrivilegesMap.entrySet());
        // sort the entries by the most shallow depth of the contained privileges
        Collections.sort(sortedEntries, (e1, e2) -> {
                        int shallowestDepth1 = Integer.MAX_VALUE;
                        for (LocalPrivilege lp : e1.getValue()) {
                            Integer depth = privilegeLongestDepthMap.get(lp.getPrivilege());
                            if (depth != null && depth.intValue() < shallowestDepth1) {
                                shallowestDepth1 = depth.intValue();
                            }
                        }
                        int shallowestDepth2 = Integer.MAX_VALUE;
                        for (LocalPrivilege lp : e2.getValue()) {
                            Integer depth = privilegeLongestDepthMap.get(lp.getPrivilege());
                            if (depth != null && depth.intValue() < shallowestDepth2) {
                                shallowestDepth2 = depth.intValue();
                            }
                        }
                        return Integer.compare(shallowestDepth1, shallowestDepth2);
                    });

        for (Entry<Set<LocalRestriction>, List<LocalPrivilege>> entry: sortedEntries) {
            Set<Privilege> privilegesSet = new HashSet<>();
            Map<String, Value> restrictions = new HashMap<>(); 
            Map<String, Value[]> mvRestrictions = new HashMap<>();

            Set<LocalRestriction> localRestrictions = entry.getKey();
            for (LocalRestriction localRestriction : localRestrictions) {
                if (localRestriction.isMultiValue()) {
                    mvRestrictions.put(localRestriction.getName(), localRestriction.getValues());
                } else {
                    restrictions.put(localRestriction.getName(), localRestriction.getValue());
                }
            }

            for (LocalPrivilege localPrivilege : entry.getValue()) {
                privilegesSet.add(localPrivilege.getPrivilege());
            }

            if (!privilegesSet.isEmpty()) {
                if (acl instanceof PrincipalAccessControlList) {
                    ((PrincipalAccessControlList)acl).addEntry(resourcePath, privilegesSet.toArray(new Privilege[privilegesSet.size()]), restrictions, mvRestrictions);
                } else {
                    acl.addEntry(principal, privilegesSet.toArray(new Privilege[privilegesSet.size()]), isAllow, restrictions, mvRestrictions);
                }
            }
        }
    }

    /**
     * Move the ACE(s) for the specified principal to the position specified by the 'order'
     * parameter. This is a copy of the private AccessControlUtil.reorderAccessControlEntries method.
     *
     * @param acl the acl of the node containing the ACE to position
     * @param principal the user or group of the ACE to position
     * @param order where the access control entry should go in the list.
     *         Value should be one of these:
     *         <table>
     *          <caption>Values</caption>
     *          <tr><td>first</td><td>Place the target ACE as the first amongst its siblings</td></tr>
     *          <tr><td>last</td><td>Place the target ACE as the last amongst its siblings</td></tr>
     *          <tr><td>before xyz</td><td>Place the target ACE immediately before the sibling whose name is xyz</td></tr>
     *          <tr><td>after xyz</td><td>Place the target ACE immediately after the sibling whose name is xyz</td></tr>
     *          <tr><td>numeric</td><td>Place the target ACE at the specified index</td></tr>
     *         </table>
     * @throws RepositoryException
     * @throws UnsupportedRepositoryOperationException
     * @throws AccessControlException
     */
    private static void reorderAccessControlEntries(AccessControlList acl,
            Principal principal, String order) throws RepositoryException {
        if (order == null || order.length() == 0) {
            return; //nothing to do
        }
        if (acl instanceof JackrabbitAccessControlList) {
            JackrabbitAccessControlList jacl = (JackrabbitAccessControlList)acl;

            AccessControlEntry[] accessControlEntries = jacl.getAccessControlEntries();
            if (accessControlEntries.length <= 1) {
                return; //only one ACE, so nothing to reorder.
            }

            AccessControlEntry beforeEntry = null;
            if ("first".equals(order)) {
                beforeEntry = accessControlEntries[0];
            } else if ("last".equals(order)) {
                // add to the end is the same as default
            } else if (order.startsWith("before ")) {
                String beforePrincipalName = order.substring(7);

                //find the index of the ACE of the 'before' principal
                for (int i=0; i < accessControlEntries.length; i++) {
                    if (beforePrincipalName.equals(accessControlEntries[i].getPrincipal().getName())) {
                        //found it!
                        beforeEntry = accessControlEntries[i];
                        break;
                    }
                }

                if (beforeEntry == null) {
                    //didn't find an ACE that matched the 'before' principal
                    throw new IllegalArgumentException("No ACE was found for the specified principal: " + beforePrincipalName);
                }
            } else if (order.startsWith("after ")) {
                String afterPrincipalName = order.substring(6);

                //find the index of the ACE of the 'after' principal
                for (int i = accessControlEntries.length - 1; i >= 0; i--) {
                    if (afterPrincipalName.equals(accessControlEntries[i].getPrincipal().getName())) {
                        //found it!

                        // the 'before' ACE is the next one after the 'after' ACE
                        if (i >= accessControlEntries.length - 1) {
                            //the after is the last one in the list
                            beforeEntry = null;
                        } else {
                            beforeEntry = accessControlEntries[i + 1];
                        }
                        break;
                    }
                }

                if (beforeEntry == null) {
                    //didn't find an ACE that matched the 'after' principal
                    throw new IllegalArgumentException("No ACE was found for the specified principal: " + afterPrincipalName);
                }
            } else {
                int index = -1;
                try {
                    index = Integer.parseInt(order);
                } catch (NumberFormatException nfe) {
                    //not a number.
                    throw new IllegalArgumentException("Illegal value for the order parameter: " + order);
                }
                if (index > accessControlEntries.length) {
                    //invalid index
                    throw new IndexOutOfBoundsException("Index value is too large: " + index);
                }

                //the index value is the index of the principal.  A principal may have more
                // than one ACEs (deny + grant), so we need to compensate.
                Map<Principal, Integer> principalToIndex = new HashMap<>();
                for (int i = 0; i < accessControlEntries.length; i++) {
                    Principal principal2 = accessControlEntries[i].getPrincipal();
                    Integer idx = i;
                    principalToIndex.computeIfAbsent(principal2, key -> idx);
                }
                Integer[] sortedIndexes = principalToIndex.values().stream()
                        .sorted()
                        .toArray(size -> new Integer[size]);
                if (index >= 0 && index < sortedIndexes.length - 1) {
                    int idx = sortedIndexes[index];
                    beforeEntry = accessControlEntries[idx];
                }
            }

            if (beforeEntry != null) {
                //now loop through the entries to move the affected ACEs to the specified
                // position.
                for (AccessControlEntry ace : accessControlEntries) {
                    if (principal.equals(ace.getPrincipal())) {
                        //this ACE is for the specified principal.
                        jacl.orderBefore(ace, beforeEntry);
                    }
                }
            }
        } else {
            throw new IllegalArgumentException("The acl must be an instance of JackrabbitAccessControlList");
        }
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
        modifyAce(jcrSession, resourcePath, principalId, privileges, order, 
                restrictions, mvRestrictions, removeRestrictionNames, autoSave, null);
    }

    protected void modifyAce( // NOSONAR
            Session jcrSession, String resourcePath, String principalId, Map<String, String> privileges,
            String order, Map<String, Value> restrictions, Map<String, Value[]> mvRestrictions,
            Set<String> removeRestrictionNames, boolean autoSave, List<Modification> changes) throws RepositoryException {

        Principal principal = validateArgs(jcrSession, resourcePath, principalId);

        // Calculate a map of restriction names to the restriction definition.
        // Use for fast lookup during the calls below.
        AccessControlManager acm = jcrSession.getAccessControlManager();
        Map<String, RestrictionDefinition> srMap = buildRestrictionNameToDefinitionMap(resourcePath);
        Map<Privilege, Integer> privilegeLongestDepthMap = PrivilegesHelper.buildPrivilegeLongestDepthMap(acm.privilegeFromName(PrivilegeConstants.JCR_ALL));

        // first calculate what is currently stored in the ace
        Map<Privilege, LocalPrivilege> privilegeToLocalPrivilegesMap = loadStoredAce(acm, resourcePath, principal, srMap);

        //process the restrictions to remove
        for (LocalPrivilege lp : privilegeToLocalPrivilegesMap.values()) {
            if (lp.isAllow()) {
                PrivilegesHelper.unallowRestrictions(privilegeToLocalPrivilegesMap, removeRestrictionNames, Collections.singleton(lp.getPrivilege()));
            }
            if (lp.isDeny()) {
                PrivilegesHelper.undenyRestrictions(privilegeToLocalPrivilegesMap, removeRestrictionNames, Collections.singleton(lp.getPrivilege()));
            }
        }

        // process the new restrictions
        Set<LocalRestriction> localRestrictions = new HashSet<>();
        if (restrictions != null) {
            for (Entry<String, Value> entry : restrictions.entrySet()) {
                RestrictionDefinition rd = srMap.get(entry.getKey());
                if (rd == null) {
                    //illegal restriction name?
                    throw new AccessControlException(INVALID_OR_NOT_SUPPORTED_RESTRICTION_NAME_WAS_SUPPLIED);
                }
                localRestrictions.add(new LocalRestriction(rd, entry.getValue()));
            }
        }
        if (mvRestrictions != null) {
            for (Entry<String, Value[]> entry : mvRestrictions.entrySet()) {
                RestrictionDefinition rd = srMap.get(entry.getKey());
                if (rd == null) {
                    //illegal restriction name?
                    throw new AccessControlException(INVALID_OR_NOT_SUPPORTED_RESTRICTION_NAME_WAS_SUPPLIED);
                }
                localRestrictions.add(new LocalRestriction(rd, entry.getValue()));
            }
        }

        // map the values to the privileges with that value
        Map<PrivilegeValues, Set<Privilege>> privilegeValueToPrivilegesMap = new EnumMap<>(PrivilegeValues.class);
        for (Entry<String, String> entry : privileges.entrySet()) {
            String privilegeName = entry.getKey();
            // for backward compatibility, deal with a prefixed value 
            if (privilegeName.startsWith("privilege@")) {
                privilegeName = privilegeName.substring(10);
            }
            Privilege privilege = acm.privilegeFromName(privilegeName);
            PrivilegeValues value = PrivilegeValues.valueOfParam(entry.getValue());
            Set<Privilege> privilegesSet = privilegeValueToPrivilegesMap.computeIfAbsent(value, k -> new HashSet<>());
            privilegesSet.add(privilege);
        }

        // process the new privileges
        for (Entry<PrivilegeValues, Set<Privilege>> entry : privilegeValueToPrivilegesMap.entrySet()) {
            switch (entry.getKey()) {
            case GRANTED:
            case ALLOW:
                PrivilegesHelper.allow(privilegeToLocalPrivilegesMap, localRestrictions, entry.getValue());
                break;
            case DENIED:
            case DENY:
                PrivilegesHelper.deny(privilegeToLocalPrivilegesMap, localRestrictions, entry.getValue());
                break;
            case NONE:
                PrivilegesHelper.none(privilegeToLocalPrivilegesMap, entry.getValue());
                break;
            default:
                break;
            }
        }

        // combine any aggregates that are still valid
        PrivilegesHelper.consolidateAggregates(jcrSession, resourcePath, privilegeToLocalPrivilegesMap, privilegeLongestDepthMap);

        modifyAce(jcrSession, resourcePath, principalId, 
                privilegeToLocalPrivilegesMap.values(), order, 
                autoSave, changes);
    }

    /* (non-Javadoc)
     * @see org.apache.sling.jcr.jackrabbit.accessmanager.ModifyAce#modifyAce(javax.jcr.Session, java.lang.String, java.lang.String, java.util.Collection, java.lang.String, boolean)
     */
    @Override
    public void modifyAce(
            Session jcrSession, String resourcePath, String principalId, 
            Collection<LocalPrivilege> localPrivileges, String order, 
            boolean autoSave) throws RepositoryException {
        modifyAce(jcrSession, resourcePath, principalId, 
                localPrivileges, order, 
                autoSave, null);
    }

    protected void modifyAce(
            Session jcrSession, String resourcePath, String principalId, 
            Collection<LocalPrivilege> localPrivileges, String order, 
            boolean autoSave, List<Modification> changes) throws RepositoryException {
        @NotNull
        Principal principal = validateArgs(jcrSession, resourcePath, principalId);

        // build a list of each of the LocalPrivileges that have the same restrictions
        Map<Set<LocalRestriction>, List<LocalPrivilege>> allowRestrictionsToLocalPrivilegesMap = new HashMap<>();
        Map<Set<LocalRestriction>, List<LocalPrivilege>> denyRestrictionsToLocalPrivilegesMap = new HashMap<>();
        for (LocalPrivilege localPrivilege: localPrivileges) {
            if (localPrivilege.isAllow()) {
                List<LocalPrivilege> list = allowRestrictionsToLocalPrivilegesMap.computeIfAbsent(localPrivilege.getAllowRestrictions(), key -> new ArrayList<>());
                list.add(localPrivilege);
            }
            if (localPrivilege.isDeny()) {
                List<LocalPrivilege> list = denyRestrictionsToLocalPrivilegesMap.computeIfAbsent(localPrivilege.getDenyRestrictions(), key -> new ArrayList<>());
                list.add(localPrivilege);
            }
        }

        try {
            // Get or create the ACL for the node.
            AccessControlManager acm = jcrSession.getAccessControlManager();
            JackrabbitAccessControlList acl = getAcl(acm, resourcePath, principal);

            // remove all the old aces for the principal
            order = removeAces(resourcePath, order, principal, acl);

            // now add all the new aces that we have collected
            Map<Privilege, Integer> privilegeLongestDepthMap = PrivilegesHelper.buildPrivilegeLongestDepthMap(acm.privilegeFromName(PrivilegeConstants.JCR_ALL));
            addAces(resourcePath, principal, denyRestrictionsToLocalPrivilegesMap, false, acl, privilegeLongestDepthMap);
            addAces(resourcePath, principal, allowRestrictionsToLocalPrivilegesMap, true, acl, privilegeLongestDepthMap);

            // reorder the aces
            reorderAccessControlEntries(acl, principal, order);

            // Store the actual changes.
            acm.setPolicy(acl.getPath(), acl);

            if (changes != null) {
                changes.add(Modification.onModified(principal.getName()));
            }

            if (autoSave && jcrSession.hasPendingChanges()) {
                jcrSession.save();
            }
        } catch (RepositoryException re) {
            throw new RepositoryException("Failed to create ace.", re);
        }
    }

}
