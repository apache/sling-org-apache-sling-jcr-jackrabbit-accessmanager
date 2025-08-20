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
package org.apache.sling.jcr.jackrabbit.accessmanager;

import javax.jcr.Value;
import javax.jcr.security.Privilege;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import org.jetbrains.annotations.NotNull;

/**
 * Use to holds details of a privilege
 */
public class LocalPrivilege {
    private Privilege privilege;
    private boolean allow;
    private boolean deny;
    private Set<LocalRestriction> allowRestrictions = Collections.emptySet();
    private Set<LocalRestriction> denyRestrictions = Collections.emptySet();

    public LocalPrivilege(@NotNull Privilege privilege) {
        this.privilege = privilege;
    }

    public Privilege getPrivilege() {
        return privilege;
    }

    public String getName() {
        return privilege.getName();
    }

    public boolean isNone() {
        return !allow && !deny;
    }

    public boolean isAllow() {
        return allow;
    }

    public boolean isDeny() {
        return deny;
    }

    public void setAllow(boolean allow) {
        this.allow = allow;
    }

    public void setDeny(boolean deny) {
        this.deny = deny;
    }

    public Set<LocalRestriction> getAllowRestrictions() {
        return Collections.unmodifiableSet(allowRestrictions);
    }

    public Set<LocalRestriction> getDenyRestrictions() {
        return Collections.unmodifiableSet(denyRestrictions);
    }

    protected Set<LocalRestriction> mergeRestrictions(
            Set<LocalRestriction> currentRestrictions, Set<LocalRestriction> newRestrictions) {
        Set<LocalRestriction> mergedRestrictons;
        if (newRestrictions == null) {
            mergedRestrictons = null;
        } else {
            mergedRestrictons = new HashSet<>(currentRestrictions);
            for (LocalRestriction lr : newRestrictions) {
                if (lr.isMultiValue()) {
                    String expectedName = lr.getName();
                    Optional<LocalRestriction> existing = currentRestrictions.stream()
                            .filter(r -> r.getName().equals(expectedName))
                            .findFirst();
                    if (existing.isPresent()) {
                        // remove the old one that we are replacing
                        mergedRestrictons.removeIf(k -> expectedName.equals(k.getName()));

                        Set<Value> mergedValues = new LinkedHashSet<>();
                        // add the current values
                        LocalRestriction existingLr = existing.get();
                        Stream.of(existingLr.getValues()).forEach(mergedValues::add);
                        // merge the new values
                        Stream.of(lr.getValues()).forEach(mergedValues::add);
                        Value[] newValues = mergedValues.toArray(new Value[mergedValues.size()]);
                        // construct the replacement object
                        lr = LocalRestriction.cloneWithNewValues(lr, newValues);
                    }
                }
                // add to the set
                mergedRestrictons.add(lr);
            }
        }
        return mergedRestrictons;
    }

    public void setAllowRestrictions(Set<LocalRestriction> restrictions) {
        this.allowRestrictions = mergeRestrictions(this.allowRestrictions, restrictions);
    }

    public void setDenyRestrictions(Set<LocalRestriction> restrictions) {
        this.denyRestrictions = mergeRestrictions(this.denyRestrictions, restrictions);
    }

    public void unsetAllowRestrictions(Collection<String> restrictionNames) {
        this.allowRestrictions.removeIf(k -> restrictionNames.contains(k.getName()));
    }

    public void unsetDenyRestrictions(Collection<String> restrictionNames) {
        this.denyRestrictions.removeIf(k -> restrictionNames.contains(k.getName()));
    }

    public void clearAllowRestrictions() {
        this.allowRestrictions.clear();
    }

    public void clearDenyRestrictions() {
        this.denyRestrictions.clear();
    }

    /**
     * compares if restrictions present is same as specified restrictions in the
     * supplied argument
     *
     * @param otherAllowRestrictions the other restrictions set to compare to
     * @return true or false
     */
    public boolean sameAllowRestrictions(Set<LocalRestriction> otherAllowRestrictions) {
        boolean same = false;
        // total (multivalue and simple)  number of restrictions should be same
        if (allowRestrictions.size() == otherAllowRestrictions.size()
                && allowRestrictions.containsAll(otherAllowRestrictions)) {
            // allow and deny list seems to be the same
            same = true;
        }
        return same;
    }

    /**
     * compares if restrictions present is same as specified restrictions in the
     * supplied argument
     *
     * @param otherDenyRestrictions the other restrictions set to compare to
     * @return true or false
     */
    public boolean sameDenyRestrictions(Set<LocalRestriction> otherDenyRestrictions) {
        boolean same = false;
        // total (multivalue and simple)  number of restrictions should be same
        if (denyRestrictions.size() == otherDenyRestrictions.size()
                && denyRestrictions.containsAll(otherDenyRestrictions)) {
            // allow and deny list seems to be the same
            same = true;
        }
        return same;
    }

    /**
     * compares if allow and deny restrictions are the same
     *
     * @return true or false
     */
    public boolean sameAllowAndDenyRestrictions() {
        boolean same = false;
        // total (multivalue and simple)  number of restrictions should be same
        if (allowRestrictions.size() == denyRestrictions.size() && allowRestrictions.containsAll(denyRestrictions)) {
            // allow and deny list seems to be the same
            same = true;
        }
        return same;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("LocalPrivilege [name=");
        builder.append(getName());
        builder.append(", allow=");
        builder.append(allow);
        builder.append(", deny=");
        builder.append(deny);
        builder.append(", allowRestrictions=");
        builder.append(allowRestrictions);
        builder.append(", denyRestrictions=");
        builder.append(denyRestrictions);
        builder.append("]");
        return builder.toString();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (allow ? 1231 : 1237);
        result = prime * result + ((allowRestrictions == null) ? 0 : allowRestrictions.hashCode());
        result = prime * result + (deny ? 1231 : 1237);
        result = prime * result + ((denyRestrictions == null) ? 0 : denyRestrictions.hashCode());
        result = prime * result + ((privilege == null) ? 0 : privilege.getName().hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        LocalPrivilege other = (LocalPrivilege) obj;
        if (allow != other.allow) return false;
        if (allowRestrictions == null) {
            if (other.allowRestrictions != null) return false;
        } else if (!allowRestrictions.equals(other.allowRestrictions)) return false;
        if (deny != other.deny) return false;
        if (denyRestrictions == null) {
            if (other.denyRestrictions != null) return false;
        } else if (!denyRestrictions.equals(other.denyRestrictions)) return false;
        if (privilege == null) {
            if (other.privilege != null) return false;
        } else if (other.privilege == null) {
            return false;
        } else if (!privilege.getName().equals(other.privilege.getName())) return false;
        return true;
    }
}
