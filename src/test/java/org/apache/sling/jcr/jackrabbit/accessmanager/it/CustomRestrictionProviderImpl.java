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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.api.Type;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.AbstractRestrictionProvider;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.Restriction;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionDefinition;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionDefinitionImpl;
import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionPattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sample implementation of the RestrictionProvider interface to test that
 * custom restrictions can be used.
 */
public class CustomRestrictionProviderImpl extends AbstractRestrictionProvider {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    public static final String SLING_CUSTOM_RESTRICTION = "sling:customRestriction";

    public CustomRestrictionProviderImpl() {
        super(supportedRestrictions());
    }

    private static Map<String, RestrictionDefinition> supportedRestrictions() {
        RestrictionDefinition slingCustomRestriction =
                new RestrictionDefinitionImpl(SLING_CUSTOM_RESTRICTION, Type.STRINGS, false);
        Map<String, RestrictionDefinition> supportedRestrictions = new HashMap<String, RestrictionDefinition>();
        supportedRestrictions.put(slingCustomRestriction.getName(), slingCustomRestriction);
        return Collections.unmodifiableMap(supportedRestrictions);
    }

    @Override
    public RestrictionPattern getPattern(String oakPath, Tree tree) {
        if (oakPath != null) {
            PropertyState resourceTypes = tree.getProperty(SLING_CUSTOM_RESTRICTION);
            if (resourceTypes != null) {
                CustomRestrictionPattern resourceTypePattern = new CustomRestrictionPattern();
                logger.trace(
                        "Returning resourceTypePattern={} for sling:customRestriction in getPattern(String,Tree)",
                        resourceTypePattern);
                return resourceTypePattern;
            }
        }
        return RestrictionPattern.EMPTY;
    }

    @Override
    public RestrictionPattern getPattern(String oakPath, Set<Restriction> restrictions) {
        if (oakPath != null && !restrictions.isEmpty()) {
            for (Restriction r : restrictions) {
                String name = r.getDefinition().getName();
                if (SLING_CUSTOM_RESTRICTION.equals(name)) {
                    CustomRestrictionPattern resourceTypePattern = new CustomRestrictionPattern();
                    logger.trace(
                            "Returning resourceTypePattern={} for sling:customRestriction in getPattern(String,Set<Restriction>)",
                            resourceTypePattern);
                    return resourceTypePattern;
                }
            }
        }

        return RestrictionPattern.EMPTY;
    }

    /** Implementation of the {@link RestrictionPattern} interface that returns {@code false} */
    public static class CustomRestrictionPattern implements RestrictionPattern {

        @Override
        public boolean matches(Tree tree, PropertyState property) {
            return false;
        }

        @Override
        public boolean matches(String path) {
            return false;
        }

        @Override
        public boolean matches() {
            return false;
        }
    }
}
