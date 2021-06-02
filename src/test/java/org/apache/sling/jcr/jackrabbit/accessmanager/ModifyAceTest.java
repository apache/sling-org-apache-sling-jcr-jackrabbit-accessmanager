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
package org.apache.sling.jcr.jackrabbit.accessmanager;

import java.util.Map;

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.UnsupportedRepositoryOperationException;

import org.junit.Test;

/**
 * Tests to verify the ModifyAce default methods
 * for an old impl that does not provide an implementation
 * for those methods
 */
public class ModifyAceTest {

    private ModifyAce modifyAce = new ModifyAceOldImpl();

    @Test(expected = UnsupportedRepositoryOperationException.class)
    public void testModify1() throws RepositoryException {
        modifyAce.modifyAce(null, null, null, null, null, false);
    }

    @Test(expected = UnsupportedRepositoryOperationException.class)
    public void testModify2()  throws RepositoryException{
        modifyAce.modifyAce(null, null, null, null, null, null, null, null);
    }

    @Test(expected = UnsupportedRepositoryOperationException.class)
    public void testModify3() throws RepositoryException {
        modifyAce.modifyAce(null, null, null, null, null, null, null, null, false);
    }

    protected static class ModifyAceOldImpl implements ModifyAce {

        @Override
        public void modifyAce(Session jcrSession, String resourcePath, String principalId, Map<String, String> privileges,
                String order) throws RepositoryException {
            throw new UnsupportedRepositoryOperationException();
        }

    }

}
