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

import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;

import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.UnsupportedRepositoryOperationException;
import javax.jcr.Value;
import javax.jcr.ValueFactory;
import javax.jcr.security.Privilege;

import org.apache.jackrabbit.value.ValueFactoryImpl;
import org.junit.Test;
import org.mockito.Mockito;

/**
 * Tests to verify the ModifyAce default methods
 * for an old impl that does not provide an implementation
 * for those methods
 */
public class ModifyAceTest {

    private ModifyAce modifyAce = new ModifyAceOldImpl();

    @Test(expected = UnsupportedRepositoryOperationException.class)
    public void testModify1() throws RepositoryException {
        modifyAce.modifyAce(Mockito.mock(Session.class), "resourcePath", "principalId",
                Map.of("privilege1", "granted"), "order", false);
    }

    @Test
    public void testModify2()  throws RepositoryException{
        modifyAce = Mockito.spy(modifyAce);
        assertThrows(UnsupportedRepositoryOperationException.class, () -> {
            ValueFactory vf = ValueFactoryImpl.getInstance();
            modifyAce.modifyAce(Mockito.mock(Session.class), "resourcePath", "principalId",
                    Map.of("privilege1", "granted"), "order", Map.of("restriction1", vf.createValue("value1")),
                    Map.of("mvRestriction", new Value[] {vf.createValue("value2")}), Set.of("removeRestrition1"));
        });
        Mockito.verify(modifyAce, times(1)).modifyAce(any(Session.class), anyString(),
                anyString(), anyMap(), anyString(), anyMap(), anyMap(), anySet(), anyBoolean());
    }

    @Test(expected = UnsupportedRepositoryOperationException.class)
    public void testModify3() throws RepositoryException {
        ValueFactory vf = ValueFactoryImpl.getInstance();
        modifyAce.modifyAce(Mockito.mock(Session.class), "resourcePath", "principalId",
                Map.of("privilege1", "granted"), "order", Map.of("restriction1", vf.createValue("value1")),
                Map.of("mvRestriction", new Value[] {vf.createValue("value2")}), Set.of("removeRestrition1"), false);
    }

    @Test(expected = UnsupportedRepositoryOperationException.class)
    public void testModify4() throws RepositoryException {
        modifyAce.modifyAce(Mockito.mock(Session.class), "resourcePath", "principalId",
                List.of(new LocalPrivilege(Mockito.mock(Privilege.class))), "order", false);
    }


    protected static class ModifyAceOldImpl implements ModifyAce {

        @Override
        public void modifyAce(Session jcrSession, String resourcePath, String principalId, Map<String, String> privileges,
                String order) throws RepositoryException {
            throw new UnsupportedRepositoryOperationException();
        }

    }

}
