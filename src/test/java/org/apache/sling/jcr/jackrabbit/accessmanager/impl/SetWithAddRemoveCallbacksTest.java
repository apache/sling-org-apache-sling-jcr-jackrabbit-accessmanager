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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.junit.Test;

/**
 * Tests for {@link SetWithAddRemoveCallbacks}
 *
 */
public class SetWithAddRemoveCallbacksTest {

    private static final class TestAddRemoveCallback implements AddRemoveCallback<String> {
        private List<String> addedItems = new ArrayList<>();
        private List<String> removedItems = new ArrayList<>();

        @Override
        public void added(String item) {
            addedItems.add(item);
        }

        @Override
        public void removed(String item) {
            removedItems.add(item);
        }

        public void reset() {
            addedItems.clear();
            removedItems.clear();
        };
    }

    private TestAddRemoveCallback addRemoveCallback = new TestAddRemoveCallback();

    SetWithAddRemoveCallbacks<String> wrap(Set<String> set) {
        return new SetWithAddRemoveCallbacks<>(set, 
                addRemoveCallback, String.class);
    }
    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.impl.SetWithAddRemoveCallbacks#size()}.
     */
    @Test
    public void testSize() {
        Set<String> set1 = new HashSet<>();
        SetWithAddRemoveCallbacks<String> setWithCallbacks1 = wrap(set1);
        assertEquals(set1.size(), setWithCallbacks1.size());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.impl.SetWithAddRemoveCallbacks#isEmpty()}.
     */
    @Test
    public void testIsEmpty() {
        Set<String> set1 = new HashSet<>();
        SetWithAddRemoveCallbacks<String> setWithCallbacks1 = wrap(set1);

        assertTrue(setWithCallbacks1.isEmpty());

        set1.add("hello");
        assertFalse(setWithCallbacks1.isEmpty());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.impl.SetWithAddRemoveCallbacks#contains(java.lang.Object)}.
     */
    @Test
    public void testContains() {
        Set<String> set1 = new HashSet<>();
        SetWithAddRemoveCallbacks<String> setWithCallbacks1 = wrap(set1);

        assertFalse(setWithCallbacks1.contains("hello"));

        set1.add("hello");
        assertTrue(setWithCallbacks1.contains("hello"));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.impl.SetWithAddRemoveCallbacks#iterator()}.
     */
    @Test
    public void testIterator() {
        Set<String> set1 = new HashSet<>();
        set1.add("hello");
        SetWithAddRemoveCallbacks<String> setWithCallbacks1 = wrap(set1);
        Iterator<String> iterator = setWithCallbacks1.iterator();
        assertNotNull(iterator);
        assertEquals("hello", iterator.next());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.impl.SetWithAddRemoveCallbacks#toArray()}.
     */
    @Test
    public void testToArray() {
        Set<String> set1 = new HashSet<>();
        SetWithAddRemoveCallbacks<String> setWithCallbacks1 = wrap(set1);

        assertArrayEquals(new String[0], setWithCallbacks1.toArray());

        set1.add("hello");
        assertArrayEquals(new String[] { "hello" }, setWithCallbacks1.toArray());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.impl.SetWithAddRemoveCallbacks#toArray(T[])}.
     */
    @Test
    public void testToArrayTArray() {
        Set<String> set1 = new HashSet<>();
        SetWithAddRemoveCallbacks<String> setWithCallbacks1 = wrap(set1);

        assertArrayEquals(new String[0], setWithCallbacks1.toArray());

        set1.add("hello");
        assertArrayEquals(new String[] { "hello" }, setWithCallbacks1.toArray(new String[1]));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.impl.SetWithAddRemoveCallbacks#add(java.lang.Object)}.
     */
    @Test
    public void testAdd() {
        Set<String> set1 = new HashSet<>();
        SetWithAddRemoveCallbacks<String> setWithCallbacks1 = wrap(set1);

        addRemoveCallback.reset();
        assertEquals(0, addRemoveCallback.addedItems.size());
        setWithCallbacks1.add("item1");
        assertEquals(1, addRemoveCallback.addedItems.size());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.impl.SetWithAddRemoveCallbacks#remove(java.lang.Object)}.
     */
    @SuppressWarnings("unlikely-arg-type")
    @Test
    public void testRemove() {
        Set<String> set1 = new HashSet<>();
        SetWithAddRemoveCallbacks<String> setWithCallbacks1 = wrap(set1);

        set1.add("hello");
        set1.add("hello2");

        addRemoveCallback.reset();
        assertEquals(0, addRemoveCallback.removedItems.size());
        setWithCallbacks1.remove("hello");
        assertEquals(1, addRemoveCallback.removedItems.size());

        addRemoveCallback.reset();
        assertEquals(0, addRemoveCallback.removedItems.size());
        setWithCallbacks1.remove(Boolean.TRUE);
        assertEquals(0, addRemoveCallback.removedItems.size());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.impl.SetWithAddRemoveCallbacks#containsAll(java.util.Collection)}.
     */
    @Test
    public void testContainsAll() {
        Set<String> set1 = new HashSet<>();
        SetWithAddRemoveCallbacks<String> setWithCallbacks1 = wrap(set1);

        set1.add("hello");
        set1.add("hello2");
        assertTrue(setWithCallbacks1.containsAll(new HashSet<>(set1)));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.impl.SetWithAddRemoveCallbacks#addAll(java.util.Collection)}.
     */
    @Test
    public void testAddAll() {
        Set<String> set1 = new HashSet<>();
        SetWithAddRemoveCallbacks<String> setWithCallbacks1 = wrap(set1);

        addRemoveCallback.reset();
        assertEquals(0, addRemoveCallback.addedItems.size());
        setWithCallbacks1.addAll(new HashSet<>(Arrays.asList("item1", "item2")));
        assertEquals(2, addRemoveCallback.addedItems.size());

        addRemoveCallback.reset();
        assertEquals(0, addRemoveCallback.addedItems.size());
        setWithCallbacks1.addAll(null);
        assertEquals(0, addRemoveCallback.addedItems.size());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.impl.SetWithAddRemoveCallbacks#retainAll(java.util.Collection)}.
     */
    @Test
    public void testRetainAll() {
        Set<String> set1 = new HashSet<>();
        SetWithAddRemoveCallbacks<String> setWithCallbacks1 = wrap(set1);

        set1.add("hello");
        set1.add("hello2");
        assertFalse(setWithCallbacks1.isEmpty());
        addRemoveCallback.reset();
        assertEquals(0, addRemoveCallback.removedItems.size());
        setWithCallbacks1.retainAll(new HashSet<>(set1));
        assertEquals(0, addRemoveCallback.removedItems.size());

        addRemoveCallback.reset();
        assertEquals(0, addRemoveCallback.removedItems.size());
        setWithCallbacks1.retainAll(new HashSet<>());
        assertEquals(2, addRemoveCallback.removedItems.size());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.impl.SetWithAddRemoveCallbacks#removeAll(java.util.Collection)}.
     */
    @Test
    public void testRemoveAll() {
        Set<String> set1 = new HashSet<>();
        SetWithAddRemoveCallbacks<String> setWithCallbacks1 = wrap(set1);

        set1.add("hello");
        set1.add("hello2");
        assertFalse(setWithCallbacks1.isEmpty());
        addRemoveCallback.reset();
        assertEquals(0, addRemoveCallback.removedItems.size());
        setWithCallbacks1.removeAll(new HashSet<>(set1));
        assertEquals(2, addRemoveCallback.removedItems.size());
        assertTrue(setWithCallbacks1.isEmpty());

        addRemoveCallback.reset();
        assertEquals(0, addRemoveCallback.removedItems.size());
        setWithCallbacks1.removeAll(null);
        assertEquals(0, addRemoveCallback.removedItems.size());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.impl.SetWithAddRemoveCallbacks#clear()}.
     */
    @Test
    public void testClear() {
        Set<String> set1 = new HashSet<>();
        SetWithAddRemoveCallbacks<String> setWithCallbacks1 = wrap(set1);

        set1.add("hello");
        assertFalse(setWithCallbacks1.isEmpty());
        addRemoveCallback.reset();
        assertEquals(0, addRemoveCallback.removedItems.size());
        setWithCallbacks1.clear();
        assertEquals(1, addRemoveCallback.removedItems.size());
        assertTrue(setWithCallbacks1.isEmpty());
    }

}
