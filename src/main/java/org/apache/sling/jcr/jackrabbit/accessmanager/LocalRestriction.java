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
package org.apache.sling.jcr.jackrabbit.accessmanager;

import java.util.Arrays;

import javax.jcr.Value;

import org.apache.jackrabbit.oak.spi.security.authorization.restriction.RestrictionDefinition;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * Use to holds details of a restriction
 */
public class LocalRestriction {

    private RestrictionDefinition rd;
    private Value[] values;

    public LocalRestriction(@NotNull RestrictionDefinition rd, @Nullable Value value) {
        super();
        this.rd = rd;
        this.values = value == null ? null : new Value[] { value };
    }
    public LocalRestriction(@NotNull RestrictionDefinition rd, @Nullable Value[] values) {
        super();
        this.rd = rd;
        this.values = values;
    }

    public String getName() {
        return rd.getName();
    }

    public boolean isMultiValue() {
        return rd.getRequiredType().isArray();
    }

    public Value getValue() {
        Value v = null;
        if (values != null && values.length > 0) {
            v = values[0];
        }
        return v;
    }

    public Value[] getValues() {
        return values;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("LocalRestriction [name=");
        builder.append(rd == null ? null : rd.getName());
        builder.append(", value=");
        builder.append(Arrays.toString(getValues()));
        builder.append("]");
        return builder.toString();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((rd == null) ? 0 : rd.getName().hashCode());
        result = prime * result + Arrays.hashCode(values);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        LocalRestriction other = (LocalRestriction) obj;
        if (rd == null) {
            if (other.rd != null)
                return false;
        } else if (other.rd == null) {
            return false;
        } else if (!rd.getName().equals(other.rd.getName()))
            return false;
        return Arrays.equals(values, other.values);
    }

    /**
     * Clone from an existing object and then assign the new values
     */
    public static @NotNull LocalRestriction cloneWithNewValues(@NotNull LocalRestriction lr, @NotNull Value[] newValues) {
        return new LocalRestriction(lr.rd, newValues);
    }

}
