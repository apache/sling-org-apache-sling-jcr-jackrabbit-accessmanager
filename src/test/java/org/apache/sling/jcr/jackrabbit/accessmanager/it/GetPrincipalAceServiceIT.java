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

import javax.jcr.RepositoryException;

import org.apache.sling.api.resource.ResourceNotFoundException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerClass;

/**
 * Tests for the GetPrincipalAce service
 */
@RunWith(PaxExam.class)
@ExamReactorStrategy(PerClass.class)
public class GetPrincipalAceServiceIT extends PrincipalAceServiceTestSupport {

    @Test
    public void testGetPrincipalAceWithNullSessionArg() throws RepositoryException {
        assertNotNull(getPrincipalAce);
        String resourcePath = testNode.getPath();
        try {
            getPrincipalAce.getPrincipalAce(null,
                    resourcePath,
                    "everyone");
            fail("Expected RepositoryException");
        } catch (RepositoryException re) {
            assertEquals("JCR Session not found", re.getMessage());
        }
    }

    @Test
    public void testGetPrincipalAceWithNullResourcePathArg() throws RepositoryException {
        assertNotNull(getPrincipalAce);
        try {
            getPrincipalAce.getPrincipalAce(adminSession,
                    null,
                    "everyone");
            fail("Expected ResourceNotFoundException");
        } catch (ResourceNotFoundException rnfe) {
            //expected
        }
    }

    @Test
    public void testGetPrincipalAceWithNotExistingResourcePathArg() throws RepositoryException {
        assertNotNull(getPrincipalAce);
        try {
            getPrincipalAce.getPrincipalAce(adminSession,
                    "/not_a_real_path",
                    "everyone");
            fail("Expected ResourceNotFoundException");
        } catch (ResourceNotFoundException rnfe) {
            //expected
        }
    }

    @Test
    public void testGetPrincipalAceWithNullPrincipalIdArg() throws RepositoryException {
        assertNotNull(getPrincipalAce);
        String resourcePath = testNode.getPath();
        try {
            getPrincipalAce.getPrincipalAce(adminSession,
                    resourcePath,
                    null);
            fail("Expected RepositoryException");
        } catch (RepositoryException re) {
            assertEquals("principalId was not submitted.", re.getMessage());
        }
    }

    @Test
    public void testGetPrincipalAceWithNotExistingPrincipalIdArg() throws RepositoryException {
        assertNotNull(getPrincipalAce);
        String resourcePath = testNode.getPath();
        try {
            getPrincipalAce.getPrincipalAce(adminSession,
                    resourcePath,
                    "not_a_real_principalid");
            fail("Expected RepositoryException");
        } catch (RepositoryException re) {
            assertEquals("Invalid principalId was submitted.", re.getMessage());
        }
    }

}
