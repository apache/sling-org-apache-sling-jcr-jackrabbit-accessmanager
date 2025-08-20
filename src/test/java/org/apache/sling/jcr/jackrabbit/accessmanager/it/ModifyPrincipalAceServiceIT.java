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
package org.apache.sling.jcr.jackrabbit.accessmanager.it;

import javax.inject.Inject;
import javax.jcr.RepositoryException;

import java.util.Collections;
import java.util.Set;

import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.sling.api.resource.ResourceNotFoundException;
import org.apache.sling.jcr.jackrabbit.accessmanager.LocalPrivilege;
import org.apache.sling.jcr.jackrabbit.accessmanager.ModifyPrincipalAce;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

/**
 * Tests for the ModifyPrincipalAce service
 */
@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class ModifyPrincipalAceServiceIT extends PrincipalAceServiceTestSupport {

    @Inject
    protected ModifyPrincipalAce modifyPrincipalAce;

    @Test
    public void testModifyPrincipalAceWithNullSessionArg() throws RepositoryException {
        assertNotNull(modifyPrincipalAce);
        LocalPrivilege localPrivilege = new LocalPrivilege(
                adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ));
        localPrivilege.setAllow(true);
        String resourcePath = testNode.getPath();
        try {
            modifyPrincipalAce.modifyPrincipalAce(
                    null, resourcePath, "pacetestuser", Collections.singleton(localPrivilege), false);
            fail("Expected RepositoryException");
        } catch (RepositoryException re) {
            assertEquals("JCR Session not found", re.getMessage());
        }
    }

    @Test
    public void testModifyPrincipalAceWithNullResourcePathArg() throws RepositoryException {
        assertNotNull(modifyPrincipalAce);
        LocalPrivilege localPrivilege = new LocalPrivilege(
                adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ));
        localPrivilege.setAllow(true);
        Set<LocalPrivilege> privileges = Collections.singleton(localPrivilege);
        try {
            modifyPrincipalAce.modifyPrincipalAce(adminSession, null, "pacetestuser", privileges, false);
        } catch (ResourceNotFoundException rnfe) {
            fail("Did not expect ResourceNotFoundException");
        }
    }

    @Test
    public void testModifyPrincipalAceWithNotExistingResourcePathArg() throws RepositoryException {
        assertNotNull(modifyPrincipalAce);
        LocalPrivilege localPrivilege = new LocalPrivilege(
                adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ));
        localPrivilege.setAllow(true);
        Set<LocalPrivilege> privileges = Collections.singleton(localPrivilege);
        try {
            modifyPrincipalAce.modifyPrincipalAce(adminSession, "/not_a_real_path", "pacetestuser", privileges, false);
        } catch (ResourceNotFoundException rnfe) {
            fail("Did not expect ResourceNotFoundException");
        }
    }

    @Test
    public void testModifyPrincipalAceWithNullPrincipalIdArg() throws RepositoryException {
        assertNotNull(modifyPrincipalAce);
        LocalPrivilege localPrivilege = new LocalPrivilege(
                adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ));
        localPrivilege.setAllow(true);
        Set<LocalPrivilege> privileges = Collections.singleton(localPrivilege);
        String resourcePath = testNode.getPath();
        try {
            modifyPrincipalAce.modifyPrincipalAce(adminSession, resourcePath, null, privileges, false);
            fail("Expected RepositoryException");
        } catch (RepositoryException re) {
            assertEquals("principalId was not submitted.", re.getMessage());
        }
    }

    @Test
    public void testModifyPrincipalAceWithNotExistingPrincipalIdArg() throws RepositoryException {
        assertNotNull(modifyPrincipalAce);
        LocalPrivilege localPrivilege = new LocalPrivilege(
                adminSession.getAccessControlManager().privilegeFromName(PrivilegeConstants.JCR_READ));
        localPrivilege.setAllow(true);
        String resourcePath = testNode.getPath();
        try {
            modifyPrincipalAce.modifyPrincipalAce(
                    adminSession, resourcePath, "not_a_real_principalid", Collections.singleton(localPrivilege), false);
            fail("Expected RepositoryException");
        } catch (RepositoryException re) {
            assertEquals("Invalid principalId was submitted.", re.getMessage());
        }
    }
}
