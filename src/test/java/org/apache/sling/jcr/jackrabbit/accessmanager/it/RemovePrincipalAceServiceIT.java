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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import javax.inject.Inject;
import javax.jcr.RepositoryException;

import org.apache.sling.api.resource.ResourceNotFoundException;
import org.apache.sling.jcr.jackrabbit.accessmanager.DeletePrincipalAces;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;

/**
 * Tests for the DeletePrincipalAces service
 */
@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class RemovePrincipalAceServiceIT extends PrincipalAceServiceTestSupport {

    @Inject
    private DeletePrincipalAces deletePrincipalAces;

    @Test
    public void testDeletePrincipalAceWithNullSessionArg() throws RepositoryException {
        assertNotNull(deletePrincipalAces);
        String resourcePath = testNode.getPath();
        try {
            deletePrincipalAces.deletePrincipalAces(null,
                    resourcePath,
                    new String [] {"everyone"});
            fail("Expected RepositoryException");
        } catch (RepositoryException re) {
            assertEquals("JCR Session not found", re.getMessage());
        }
    }

    @Test
    public void testDeletePrincipalAceWithNullResourcePathArg() throws RepositoryException {
        assertNotNull(deletePrincipalAces);
        try {
            deletePrincipalAces.deletePrincipalAces(adminSession,
                    null,
                    new String [] {"everyone"});
        } catch (ResourceNotFoundException rnfe) {
            //expected
            fail("Did not expect ResourceNotFoundException");
        }
    }

    @Test
    public void testDeletePrincipalAceWithNotExistingResourcePathArg() throws RepositoryException {
        assertNotNull(deletePrincipalAces);
        try {
            deletePrincipalAces.deletePrincipalAces(adminSession,
                    "/not_a_real_path",
                    new String [] {"everyone"});
        } catch (ResourceNotFoundException rnfe) {
            //expected
            fail("Did not expect ResourceNotFoundException");
        }
    }

    @Test
    public void testDeletePrincipalAceWithNullPrincipalIdArg() throws RepositoryException {
        assertNotNull(deletePrincipalAces);
        String resourcePath = testNode.getPath();
        try {
            deletePrincipalAces.deletePrincipalAces(adminSession,
                    resourcePath,
                    null);
            fail("Expected RepositoryException");
        } catch (RepositoryException re) {
            assertEquals("principalIds were not sumitted.", re.getMessage());
        }
    }

    @Test
    public void testDeletePrincipalAceWithNotExistingPrincipalIdArg() throws RepositoryException {
        assertNotNull(deletePrincipalAces);
        String resourcePath = testNode.getPath();
        try {
            deletePrincipalAces.deletePrincipalAces(adminSession,
                    resourcePath,
                    new String[] {"not_a_real_principalid"});
            fail("Expected RepositoryException");
        } catch (RepositoryException re) {
            assertEquals("Invalid principalId was submitted.", re.getMessage());
        }
    }

}
