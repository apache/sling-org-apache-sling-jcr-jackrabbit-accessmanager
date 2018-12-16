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
package org.apache.sling.jcr.jackrabbit.accessmanager;

import java.util.Map;
import java.util.Set;

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.UnsupportedRepositoryOperationException;
import javax.jcr.Value;

/**
 * The <code>ModifyAce</code> service api.
 * <p>
 * This interface is not intended to be implemented by bundles. It is
 * implemented by this bundle and may be used by client bundles.
 * </p>
 */
public interface ModifyAce {

	/**
	 * Add or modify the access control entry for the specified user 
	 * or group.
	 * 
	 * @param jcrSession the JCR session of the user updating the user
	 * @param resourcePath The absolute path of the resource to apply the ACE to (required)
	 * @param principalId The name of the user/group to provision (required)
	 * @param privileges Map of privileges to apply. (optional)
     * @param order where the access control entry should go in the list.
     *         Value should be one of these:
     *         <table>
     *          <tr><td>null</td><td>If the ACE for the principal doesn't exist add at the end, otherwise leave the ACE at it's current position.</td></tr>
     * 			<tr><td>first</td><td>Place the target ACE as the first amongst its siblings</td></tr>
	 *			<tr><td>last</td><td>Place the target ACE as the last amongst its siblings</td></tr>
	 * 			<tr><td>before xyz</td><td>Place the target ACE immediately before the sibling whose name is xyz</td></tr>
	 * 			<tr><td>after xyz</td><td>Place the target ACE immediately after the sibling whose name is xyz</td></tr>
	 * 			<tr><td>numeric</td><td>Place the target ACE at the specified numeric index</td></tr>
	 *         </table>
	 * @throws RepositoryException
	 */
	void modifyAce(Session jcrSession,
							String resourcePath,
							String principalId,
							Map<String, String> privileges,
							String order
				) throws RepositoryException;
	
	/**
	 * Add or modify the access control entry for the specified user 
	 * or group.
	 * 
	 * @param jcrSession the JCR session of the user updating the user
	 * @param resourcePath The absolute path of the resource to apply the ACE to (required)
	 * @param principalId The name of the user/group to provision (required)
	 * @param privileges Map of privileges to apply. (optional)
     * @param order where the access control entry should go in the list.
     *         Value should be one of these:
     *         <table>
     *          <tr><td>null</td><td>If the ACE for the principal doesn't exist add at the end, otherwise leave the ACE at it's current position.</td></tr>
     * 			<tr><td>first</td><td>Place the target ACE as the first amongst its siblings</td></tr>
	 *			<tr><td>last</td><td>Place the target ACE as the last amongst its siblings</td></tr>
	 * 			<tr><td>before xyz</td><td>Place the target ACE immediately before the sibling whose name is xyz</td></tr>
	 * 			<tr><td>after xyz</td><td>Place the target ACE immediately after the sibling whose name is xyz</td></tr>
	 * 			<tr><td>numeric</td><td>Place the target ACE at the specified numeric index</td></tr>
	 *         </table>
	 * @param restrictions Map of single-value restrictions to apply. (optional)
	 * @param mvRestrictions Map of multi-value restrictions to apply. (optional)
	 * @param removeRestrictionNames Set of existing restriction names to remove (optional)
	 * @throws RepositoryException
	 */
	default void modifyAce(Session jcrSession,
							String resourcePath,
							String principalId,
							Map<String, String> privileges,
							String order,
							Map<String, Value> restrictions,
							Map<String, Value[]> mvRestrictions,
							Set<String> removeRestrictionNames
				) throws RepositoryException {
		throw new UnsupportedRepositoryOperationException();
	}

}
