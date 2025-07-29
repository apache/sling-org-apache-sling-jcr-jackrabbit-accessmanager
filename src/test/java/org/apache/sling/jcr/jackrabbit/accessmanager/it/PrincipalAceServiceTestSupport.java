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
package org.apache.sling.jcr.jackrabbit.accessmanager.it;

import static org.junit.Assert.assertNotNull;

import javax.inject.Inject;
import javax.jcr.Node;
import javax.jcr.RepositoryException;

import org.apache.sling.jcr.jackrabbit.accessmanager.GetPrincipalAce;
import org.junit.After;
import org.junit.Before;

import jakarta.json.JsonObject;

/**
 * Base class for testing of the principal ACE operations
 */
public abstract class PrincipalAceServiceTestSupport extends PrincipalAceTestSupport {

    @Inject
    protected GetPrincipalAce getPrincipalAce;

    protected Node testNode;

    @Override
    @Before
    public void before() throws Exception {
        super.before();
        testNode = adminSession.getRootNode().addNode("testNode");
        adminSession.save();
    }

    @Override
    @After
    public void after() throws Exception {
        if (adminSession != null) {
            adminSession.refresh(false);
            testNode.remove();
            if (adminSession.hasPendingChanges()) {
                adminSession.save();
            }
        }
        super.after();
    }

    protected JsonObject principalAce(String path, String principalId) throws RepositoryException {
        assertNotNull(getPrincipalAce);
        JsonObject aceObject = getPrincipalAce.getPrincipalAce(adminSession, path, principalId);
        assertNotNull(aceObject);
        return aceObject;
    }

    protected JsonObject principalAcePrivleges(String path, String principalId) throws RepositoryException {
        JsonObject ace = principalAce(path, principalId);
        JsonObject privilegesObject = ace.getJsonObject("privileges");
        assertNotNull(privilegesObject);
        return privilegesObject;
    }

}
