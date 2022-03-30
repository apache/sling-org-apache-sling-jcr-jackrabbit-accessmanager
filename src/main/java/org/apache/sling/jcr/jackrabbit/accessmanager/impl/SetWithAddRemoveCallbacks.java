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
package org.apache.sling.jcr.jackrabbit.accessmanager.impl;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.jetbrains.annotations.NotNull;

/**
 * Wrap another set with callbacks whenever any item
 * is added or removed from the set.
 */
public class SetWithAddRemoveCallbacks<E> implements Set<E> {
    private Set<E> wrapped;
    private AddRemoveCallback<E> addRemoveCallback;
    private Class<E> itemsClass;

    public SetWithAddRemoveCallbacks(@NotNull Set<E> wrapped,
            @NotNull AddRemoveCallback<E> addRemoveCallback,
            @NotNull Class<E> itemsClass) {
        this.wrapped = wrapped;
        this.addRemoveCallback = addRemoveCallback;
        this.itemsClass = itemsClass;
    }

    @Override
    public int size() {
        return wrapped.size();
    }

    @Override
    public boolean isEmpty() {
        return wrapped.isEmpty();
    }

    @Override
    public boolean contains(Object o) {
        return wrapped.contains(o);
    }

    @Override
    public Iterator<E> iterator() {
        return wrapped.iterator();
    }

    @Override
    public Object[] toArray() {
        return wrapped.toArray();
    }

    @Override
    public <T> T[] toArray(T[] a) {
        return wrapped.toArray(a);
    }

    @Override
    public boolean add(E e) {
        boolean add = wrapped.add(e);
        if (add) {
            addRemoveCallback.added(e);
        }
        return add;
    }

    @Override
    public boolean remove(Object o) {
        boolean remove = wrapped.remove(o);
        if (remove && itemsClass.isInstance(o)) {
            addRemoveCallback.removed(itemsClass.cast(o));
        }
        return remove;
    }

    @Override
    public boolean containsAll(Collection<?> c) {
        return wrapped.containsAll(c);
    }

    @Override
    public boolean addAll(Collection<? extends E> c) {
        boolean modified = false;
        if (c != null) {
            for (E e : c) {
                modified |= add(e);
            }
        }
        return modified;
    }

    @Override
    public boolean retainAll(Collection<?> c) {
        Set<E> copy = new HashSet<>(this);
        boolean retainAll = wrapped.retainAll(c);
        //remove the ones that were retained
        copy.removeAll(this);
        //callback for ones that were not retained
        for (E e : copy) {
            addRemoveCallback.removed(e);
        }
        return retainAll;
    }

    @Override
    public boolean removeAll(Collection<?> c) {
        boolean modified = false;
        if (c != null) {
            for (Object e : c) {
                modified |= remove(e);
            }
        }
        return modified;
    }

    @Override
    public void clear() {
        Set<E> copy = new HashSet<>(this);
        wrapped.clear();
        for (E e : copy) {
            addRemoveCallback.removed(e);
        }
    }

}
