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

import java.util.HashSet;
import java.util.Set;

import org.apache.jackrabbit.oak.spi.security.authorization.restriction.CompositeRestrictionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionProvider;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;

/**
 * Base class for all the servlets for the AccessManager operations
 */
public abstract class AbstractAccessServlet extends SlingAllMethodsServlet {
    private static final long serialVersionUID = 6615497265938616188L;

    private transient RestrictionProvider compositeRestrictionProvider = null;
    private transient Set<RestrictionProvider> restrictionProviders = new HashSet<>();

    // @Reference
    protected void bindRestrictionProvider(RestrictionProvider rp) {
        synchronized (restrictionProviders) {
            if (restrictionProviders.add(rp)) {
                compositeRestrictionProvider = null;
            }
        }
    }
    protected void unbindRestrictionProvider(RestrictionProvider rp) {
        synchronized (restrictionProviders) {
            if (restrictionProviders.remove(rp)) {
                compositeRestrictionProvider = null;
            }
        }
    }

    /**
     * Return the RestrictionProvider service
     */
    protected RestrictionProvider getRestrictionProvider() {
        synchronized (restrictionProviders) {
            if (compositeRestrictionProvider == null) {
                compositeRestrictionProvider = CompositeRestrictionProvider.newInstance(restrictionProviders);
            }
            return compositeRestrictionProvider;
        }
    }

}
