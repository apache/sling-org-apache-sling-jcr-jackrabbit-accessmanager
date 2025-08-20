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

import javax.jcr.security.Privilege;

import java.util.Locale;

import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo.AccessRights;
import org.junit.Test;
import org.mockito.Mockito;

import static org.junit.Assert.*;

/**
 *
 */
public class PrivilegesInfoAccessRightsTest {

    private AccessRights accessRights = new AccessRights();

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo.AccessRights#getGranted()}.
     */
    @Test
    public void testGetGranted() {
        assertNotNull(accessRights.getGranted());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo.AccessRights#getDenied()}.
     */
    @Test
    public void testGetDenied() {
        assertNotNull(accessRights.getDenied());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.PrivilegesInfo.AccessRights#getPrivilegeSetDisplayName(java.util.Locale)}.
     */
    @Test
    public void testGetPrivilegeSetDisplayNameForNone() {
        assertEquals("None", accessRights.getPrivilegeSetDisplayName(Locale.getDefault()));
    }

    @Test
    public void testGetPrivilegeSetDisplayNameForCustom() {
        accessRights.getDenied().add(mockPrivilege(Privilege.JCR_LOCK_MANAGEMENT));
        assertEquals("Custom", accessRights.getPrivilegeSetDisplayName(Locale.getDefault()));
    }

    @Test
    public void testGetPrivilegeSetDisplayNameForAll() {
        accessRights.getGranted().add(mockPrivilege(PrivilegeConstants.JCR_ALL));
        assertEquals("Full Control", accessRights.getPrivilegeSetDisplayName(Locale.getDefault()));
    }

    @Test
    public void testGetPrivilegeSetDisplayNameForReadOnly() {
        accessRights.getGranted().add(mockPrivilege(PrivilegeConstants.JCR_READ));
        assertEquals("Read Only", accessRights.getPrivilegeSetDisplayName(Locale.getDefault()));
    }

    @Test
    public void testGetPrivilegeSetDisplayNameForReadWrite() {
        accessRights.getGranted().add(mockPrivilege(PrivilegeConstants.JCR_READ));
        accessRights.getGranted().add(mockPrivilege(PrivilegeConstants.JCR_WRITE));
        assertEquals("Read/Write", accessRights.getPrivilegeSetDisplayName(Locale.getDefault()));
    }

    @Test
    public void testGetPrivilegeSetDisplayNameForOther1() {
        accessRights.getGranted().add(mockPrivilege(PrivilegeConstants.JCR_READ));
        accessRights.getGranted().add(mockPrivilege(PrivilegeConstants.JCR_LOCK_MANAGEMENT));
        assertEquals("Custom", accessRights.getPrivilegeSetDisplayName(Locale.getDefault()));
    }

    @Test
    public void testGetPrivilegeSetDisplayNameForOther2() {
        accessRights.getGranted().add(mockPrivilege(PrivilegeConstants.JCR_WRITE));
        accessRights.getGranted().add(mockPrivilege(PrivilegeConstants.JCR_LOCK_MANAGEMENT));
        assertEquals("Custom", accessRights.getPrivilegeSetDisplayName(Locale.getDefault()));
    }

    @Test
    public void testGetPrivilegeSetDisplayNameForOther3() {
        accessRights.getGranted().add(mockPrivilege(PrivilegeConstants.JCR_READ));
        accessRights.getGranted().add(mockPrivilege(PrivilegeConstants.JCR_WRITE));
        accessRights.getGranted().add(mockPrivilege(PrivilegeConstants.JCR_LOCK_MANAGEMENT));
        assertEquals("Custom", accessRights.getPrivilegeSetDisplayName(Locale.getDefault()));
    }

    @Test
    public void testGetPrivilegeSetDisplayNameForNonRootLocale() {
        assertEquals("None", accessRights.getPrivilegeSetDisplayName(Locale.ROOT));
        // call again to use the cached resourceBundle field
        assertEquals("None", accessRights.getPrivilegeSetDisplayName(Locale.ROOT));
        // try again with a different locale to recalculate the resourceBundle field
        assertEquals("None", accessRights.getPrivilegeSetDisplayName(Locale.ENGLISH));
    }

    private Privilege mockPrivilege(String name) {
        Privilege privilege = Mockito.mock(Privilege.class);
        Mockito.when(privilege.getName()).thenReturn(name);
        return privilege;
    }
}
