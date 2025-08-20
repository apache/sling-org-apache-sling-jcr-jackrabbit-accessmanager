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

import static org.junit.Assert.*;

import org.apache.jackrabbit.oak.spi.security.authorization.restriction.CompositeRestrictionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.sling.jcr.jackrabbit.accessmanager.it.CustomRestrictionProviderImpl;
import org.junit.Test;

/**
 * Simple test of the common AbstractAccessServlet
 */
public class AbstractAccessServletTest {
    private TestAccessServlet tas = new TestAccessServlet();

    @Test
    public void testBindRestrictionProvider() {
        //starts out empty
        assertEquals("Expected the empty RestrictionProvider", RestrictionProvider.EMPTY, tas.getRestrictionProvider());

        //switch from empty to the single custom restriction provider
        CustomRestrictionProviderImpl customRestrictionProvider = new CustomRestrictionProviderImpl();
        tas.bindRestrictionProvider(customRestrictionProvider);
        assertEquals("Expected the custom RestrictionProvider", customRestrictionProvider, tas.getRestrictionProvider());

        //binding the same again doesn't change the state
        tas.bindRestrictionProvider(customRestrictionProvider);
        assertEquals("Expected the custom RestrictionProvider", customRestrictionProvider, tas.getRestrictionProvider());

        // binding a second unique obj switces to a CompositeRestrictionProvider
        CustomRestrictionProviderImpl customRestrictionProvider2 = new CustomRestrictionProviderImpl();
        tas.bindRestrictionProvider(customRestrictionProvider2);
        assertNotEquals("Expected the custom RestrictionProvider", customRestrictionProvider, tas.getRestrictionProvider());
        assertTrue(tas.getRestrictionProvider() instanceof CompositeRestrictionProvider);
    }

    @Test
    public void testUnbindRestrictionProvider() {
        CustomRestrictionProviderImpl customRestrictionProvider = new CustomRestrictionProviderImpl();
        tas.bindRestrictionProvider(customRestrictionProvider);
        CustomRestrictionProviderImpl customRestrictionProvider2 = new CustomRestrictionProviderImpl();
        tas.bindRestrictionProvider(customRestrictionProvider2);

        //unbinding one of them switches back to last one left
        tas.unbindRestrictionProvider(customRestrictionProvider2);
        assertEquals("Expected the custom RestrictionProvider", customRestrictionProvider, tas.getRestrictionProvider());

        //unbinding the same again doesn't change the state
        tas.unbindRestrictionProvider(customRestrictionProvider2);
        assertEquals("Expected the custom RestrictionProvider", customRestrictionProvider, tas.getRestrictionProvider());

        //unbinding the second one switches back to empty
        tas.unbindRestrictionProvider(customRestrictionProvider);
        assertEquals("Expected the empty RestrictionProvider", RestrictionProvider.EMPTY, tas.getRestrictionProvider());
    }

    @Test
    public void testGetRestrictionProvider() {
        assertNotNull(tas.getRestrictionProvider());
    }

    private class TestAccessServlet extends AbstractAccessServlet {
        private static final long serialVersionUID = -2948341218853558959L;
    }
}
