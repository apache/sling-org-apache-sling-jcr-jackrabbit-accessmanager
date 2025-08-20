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
package org.apache.sling.jcr.jackrabbit.accessmanager.post;

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.security.AccessControlList;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.AccessControlPolicy;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import jakarta.servlet.ServletException;
import org.apache.jackrabbit.commons.iterator.AccessControlPolicyIteratorAdapter;
import org.apache.sling.api.SlingJakartaHttpServletRequest;
import org.apache.sling.api.SlingJakartaHttpServletResponse;
import org.apache.sling.api.request.header.JakartaMediaRangeList;
import org.apache.sling.api.resource.ResourceNotFoundException;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.wrappers.JavaxToJakartaRequestWrapper;
import org.apache.sling.api.wrappers.JavaxToJakartaResponseWrapper;
import org.apache.sling.jcr.jackrabbit.accessmanager.impl.PrincipalAceHelper;
import org.apache.sling.servlethelpers.MockRequestPathInfo;
import org.apache.sling.servlethelpers.MockSlingHttpServletRequest;
import org.apache.sling.servlethelpers.MockSlingHttpServletResponse;
import org.apache.sling.servlets.post.JakartaHtmlResponse;
import org.apache.sling.servlets.post.JakartaJSONResponse;
import org.apache.sling.servlets.post.JakartaPostResponse;
import org.apache.sling.servlets.post.JakartaPostResponseCreator;
import org.apache.sling.servlets.post.Modification;
import org.apache.sling.servlets.post.SlingPostConstants;
import org.apache.sling.testing.mock.sling.ResourceResolverType;
import org.apache.sling.testing.mock.sling.junit.SlingContext;
import org.junit.Rule;
import org.junit.Test;
import org.junit.Test.None;
import org.mockito.Mockito;
import org.osgi.framework.Constants;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;

/**
 * Simple test of the common AbstractAccessPostServlet
 */
public class AbstractAccessPostServletTest {

    @Rule
    public final SlingContext context = new SlingContext(ResourceResolverType.JCR_MOCK);

    private TestAccessPostServlet taps = new TestAccessPostServlet();

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.AbstractAccessPostServlet#doPost(org.apache.sling.api.SlingJakartaHttpServletRequest, org.apache.sling.api.SlingJakartaHttpServletResponse)}.
     */
    @Test
    public void testDoPost() throws ServletException, IOException, RepositoryException {
        MockSlingHttpServletRequest request = context.request();
        MockSlingHttpServletResponse response = context.response();
        SlingJakartaHttpServletRequest jakartaRequest = JavaxToJakartaRequestWrapper.toJakartaRequest(request);
        SlingJakartaHttpServletResponse jakartaResponse = JavaxToJakartaResponseWrapper.toJakartaResponse(response);

        ResourceResolver rr = context.resourceResolver();
        Session jcrSession = rr.adaptTo(Session.class);
        jcrSession.getRootNode().addNode("content").addNode("node1");
        context.currentResource(rr.getResource("/content/node1"));

        taps = Mockito.spy(taps);
        Mockito.doAnswer(invocation -> {
                    @SuppressWarnings("unchecked")
                    List<Modification> changes = invocation.getArgument(2, List.class);
                    changes.add(Modification.onModified("/modified"));
                    changes.add(Modification.onDeleted("/deleted"));
                    changes.add(Modification.onMoved("/moveSrcPath", "/moveDestPath"));
                    changes.add(Modification.onCopied("/copySrcPath", "/copyDestPath"));
                    changes.add(Modification.onCreated("/created"));
                    changes.add(Modification.onOrder("/ordered", "beforesibling"));
                    changes.add(Modification.onCheckin("/checkin"));

                    return null;
                })
                .when(taps)
                .handleOperation(any(SlingJakartaHttpServletRequest.class), any(JakartaPostResponse.class), anyList());

        taps.doPost(jakartaRequest, jakartaResponse);

        assertEquals(SlingJakartaHttpServletResponse.SC_OK, jakartaResponse.getStatus());
    }

    @Test
    public void testDoPostWithResourceNotFound() throws ServletException, IOException, RepositoryException {
        MockSlingHttpServletRequest request = context.request();
        MockSlingHttpServletResponse response = context.response();
        SlingJakartaHttpServletRequest jakartaRequest = JavaxToJakartaRequestWrapper.toJakartaRequest(request);
        SlingJakartaHttpServletResponse jakartaResponse = JavaxToJakartaResponseWrapper.toJakartaResponse(response);

        ResourceResolver rr = context.resourceResolver();
        context.currentResource(rr.resolve("/content/node1"));

        taps = Mockito.spy(taps);
        Mockito.doThrow(ResourceNotFoundException.class)
                .when(taps)
                .handleOperation(any(SlingJakartaHttpServletRequest.class), any(JakartaPostResponse.class), anyList());

        taps.doPost(jakartaRequest, jakartaResponse);

        assertEquals(SlingJakartaHttpServletResponse.SC_NOT_FOUND, jakartaResponse.getStatus());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.AbstractAccessPostServlet#validateResourcePath(javax.jcr.Session, java.lang.String)}.
     * @throws RepositoryException
     */
    @Test
    public void testValidateResourcePath() throws RepositoryException {
        Session jcrSession = context.resourceResolver().adaptTo(Session.class);
        assertThrows(ResourceNotFoundException.class, () -> taps.validateResourcePath(jcrSession, null));
        assertThrows(ResourceNotFoundException.class, () -> taps.validateResourcePath(jcrSession, "/content/node1"));

        // should not throw ResourceNotFoundException when the node exist
        jcrSession.getRootNode().addNode("content").addNode("node1");
        taps.validateResourcePath(jcrSession, "/content/node1");
    }

    @Test(expected = None.class)
    public void testValidateResourcePathWithAllowNonExistingPath() throws RepositoryException {
        taps = Mockito.spy(taps);
        Mockito.doReturn(true).when(taps).allowNonExistingPaths();

        Session jcrSession = context.resourceResolver().adaptTo(Session.class);
        taps.validateResourcePath(jcrSession, "/content/node1");
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.AbstractAccessPostServlet#createPostResponse(org.apache.sling.api.SlingJakartaHttpServletRequest)}.
     */
    @Test
    public void testCreatePostResponseWithJakartaPostResponseCreator() {
        MockSlingHttpServletRequest request = context.request();
        SlingJakartaHttpServletRequest jakartaRequest = JavaxToJakartaRequestWrapper.toJakartaRequest(request);

        JakartaPostResponseCreator mockPostResponseCreator = Mockito.mock(JakartaPostResponseCreator.class);
        Mockito.when(mockPostResponseCreator.createPostResponse(jakartaRequest)).thenReturn(null);
        taps.bindPostResponseCreator(mockPostResponseCreator, Map.of());

        assertTrue(taps.createPostResponse(jakartaRequest) instanceof JakartaHtmlResponse);

        JakartaPostResponse mockPostResponse = Mockito.mock(JakartaPostResponse.class);
        Mockito.when(mockPostResponseCreator.createPostResponse(jakartaRequest)).thenReturn(mockPostResponse);
        assertEquals(mockPostResponse, taps.createPostResponse(jakartaRequest));
    }

    @Test
    public void testCreatePostResponseWithNoAcceptParamOrHeader() {
        MockSlingHttpServletRequest request = context.request();
        SlingJakartaHttpServletRequest jakartaRequest = JavaxToJakartaRequestWrapper.toJakartaRequest(request);

        // first with no response content type specified
        assertTrue(taps.createPostResponse(jakartaRequest) instanceof JakartaHtmlResponse);

        // again with response content type specified
        request.setResponseContentType("application/json");
        assertTrue(taps.createPostResponse(jakartaRequest) instanceof JakartaJSONResponse);
    }

    @Test
    public void testCreatePostResponseWithEmptyAcceptParamOrHeader() {
        MockSlingHttpServletRequest request = context.request();
        SlingJakartaHttpServletRequest jakartaRequest = JavaxToJakartaRequestWrapper.toJakartaRequest(request);

        request.setParameterMap(Map.of(JakartaMediaRangeList.PARAM_ACCEPT, ""));
        request.setHeader(JakartaMediaRangeList.HEADER_ACCEPT, "");
        assertTrue(taps.createPostResponse(jakartaRequest) instanceof JakartaHtmlResponse);
    }

    @Test
    public void testCreatePostResponseWithAcceptParam() {
        MockSlingHttpServletRequest request = context.request();
        SlingJakartaHttpServletRequest jakartaRequest = JavaxToJakartaRequestWrapper.toJakartaRequest(request);

        request.setParameterMap(Map.of(JakartaMediaRangeList.PARAM_ACCEPT, "application/json"));
        assertTrue(taps.createPostResponse(jakartaRequest) instanceof JakartaJSONResponse);
    }

    @Test
    public void testCreatePostResponseWithAcceptHeader() {
        MockSlingHttpServletRequest request = context.request();
        SlingJakartaHttpServletRequest jakartaRequest = JavaxToJakartaRequestWrapper.toJakartaRequest(request);

        request.setHeader(JakartaMediaRangeList.HEADER_ACCEPT, "application/json");
        assertTrue(taps.createPostResponse(jakartaRequest) instanceof JakartaJSONResponse);
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.AbstractAccessPostServlet#getRedirectUrl(jakarta.servlet.http.HttpServletRequest, org.apache.sling.servlets.post.JakartaPostResponse)}.
     */
    @Test
    public void testGetRedirectUrl() throws IOException {
        MockSlingHttpServletRequest request = context.request();
        SlingJakartaHttpServletRequest jakartaRequest = JavaxToJakartaRequestWrapper.toJakartaRequest(request);

        JakartaJSONResponse postResponse = new JakartaJSONResponse();
        assertNull(taps.getRedirectUrl(jakartaRequest, postResponse));

        request.setParameterMap(Map.of(SlingPostConstants.RP_REDIRECT_TO, "/content/node"));
        assertEquals("/content/node", taps.getRedirectUrl(jakartaRequest, postResponse));
    }

    @Test
    public void testGetRedirectUrlWithHost() throws IOException {
        MockSlingHttpServletRequest request = context.request();
        SlingJakartaHttpServletRequest jakartaRequest = JavaxToJakartaRequestWrapper.toJakartaRequest(request);

        JakartaJSONResponse postResponse = new JakartaJSONResponse();
        assertNull(taps.getRedirectUrl(jakartaRequest, postResponse));

        request.setParameterMap(Map.of(SlingPostConstants.RP_REDIRECT_TO, "https://localhost/content/node"));
        assertThrows(IOException.class, () -> taps.getRedirectUrl(jakartaRequest, postResponse));
    }

    @Test
    public void testGetRedirectUrlWithInvalidSyntax() throws IOException {
        MockSlingHttpServletRequest request = context.request();
        SlingJakartaHttpServletRequest jakartaRequest = JavaxToJakartaRequestWrapper.toJakartaRequest(request);

        JakartaJSONResponse postResponse = new JakartaJSONResponse();
        assertNull(taps.getRedirectUrl(jakartaRequest, postResponse));

        request.setParameterMap(Map.of(SlingPostConstants.RP_REDIRECT_TO, "https://"));
        assertThrows(IOException.class, () -> taps.getRedirectUrl(jakartaRequest, postResponse));
    }

    @Test
    public void testGetRedirectUrlToCreated() throws IOException {
        MockSlingHttpServletRequest request = context.request();
        SlingJakartaHttpServletRequest jakartaRequest = JavaxToJakartaRequestWrapper.toJakartaRequest(request);

        JakartaJSONResponse postResponse = new JakartaJSONResponse();
        postResponse.setPath("/content/node/node1");
        assertNull(taps.getRedirectUrl(jakartaRequest, postResponse));

        request.setParameterMap(Map.of(SlingPostConstants.RP_REDIRECT_TO, "*"));
        assertEquals("node1", taps.getRedirectUrl(jakartaRequest, postResponse));

        request.setParameterMap(Map.of(SlingPostConstants.RP_REDIRECT_TO, "/content/node/*"));
        assertEquals("/content/node/node1", taps.getRedirectUrl(jakartaRequest, postResponse));

        request.setParameterMap(Map.of(SlingPostConstants.RP_REDIRECT_TO, "/content/node/*.html"));
        assertEquals("/content/node/node1.html", taps.getRedirectUrl(jakartaRequest, postResponse));

        request.setParameterMap(Map.of(SlingPostConstants.RP_REDIRECT_TO, "/content/node/"));
        assertEquals("/content/node/node1", taps.getRedirectUrl(jakartaRequest, postResponse));

        request.setParameterMap(Map.of(SlingPostConstants.RP_REDIRECT_TO, "/content/node/other"));
        assertEquals("/content/node/other", taps.getRedirectUrl(jakartaRequest, postResponse));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.AbstractAccessPostServlet#isSetStatus(org.apache.sling.api.SlingJakartaHttpServletRequest)}.
     */
    @Test
    public void testIsSetStatus() {
        MockSlingHttpServletRequest request = context.request();
        SlingJakartaHttpServletRequest jakartaRequest = JavaxToJakartaRequestWrapper.toJakartaRequest(request);

        assertTrue(taps.isSetStatus(jakartaRequest));

        request.setParameterMap(Map.of(SlingPostConstants.RP_STATUS, SlingPostConstants.STATUS_VALUE_BROWSER));
        assertFalse(taps.isSetStatus(jakartaRequest));

        request.setParameterMap(Map.of(SlingPostConstants.RP_STATUS, SlingPostConstants.STATUS_VALUE_STANDARD));
        assertTrue(taps.isSetStatus(jakartaRequest));

        request.setParameterMap(Map.of(SlingPostConstants.RP_STATUS, "other"));
        assertTrue(taps.isSetStatus(jakartaRequest));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.AbstractAccessPostServlet#getItemPath(org.apache.sling.api.SlingJakartaHttpServletRequest)}.
     */
    @Test
    public void testGetItemPath() throws RepositoryException {
        MockSlingHttpServletRequest request = context.request();
        SlingJakartaHttpServletRequest jakartaRequest = JavaxToJakartaRequestWrapper.toJakartaRequest(request);

        ResourceResolver rr = context.resourceResolver();
        Session jcrSession = rr.adaptTo(Session.class);
        jcrSession.getRootNode().addNode("content").addNode("node1");
        context.currentResource(rr.getResource("/content/node1"));

        assertEquals("/content/node1", taps.getItemPath(jakartaRequest));
    }

    @Test
    public void testGetItemPathWithAllowNonExistingPaths() throws RepositoryException {
        taps = Mockito.spy(taps);
        Mockito.doReturn(true).when(taps).allowNonExistingPaths();

        MockSlingHttpServletRequest request = context.request();
        SlingJakartaHttpServletRequest jakartaRequest = JavaxToJakartaRequestWrapper.toJakartaRequest(request);

        ResourceResolver rr = context.resourceResolver();
        Session jcrSession = rr.adaptTo(Session.class);
        jcrSession.getRootNode().addNode("content").addNode("node1");
        context.currentResource(rr.getResource("/content/node1"));

        assertEquals("/content/node1", taps.getItemPath(jakartaRequest));

        MockRequestPathInfo rpi = (MockRequestPathInfo) jakartaRequest.getRequestPathInfo();
        rpi.setResourcePath("/content");
        context.currentResource(rr.resolve("/content/notexisting1"));
        assertEquals("/content", taps.getItemPath(jakartaRequest));

        rpi.setResourcePath(PrincipalAceHelper.RESOURCE_PATH_REPOSITORY);
        assertNull(taps.getItemPath(jakartaRequest));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.AbstractAccessPostServlet#externalizePath(org.apache.sling.api.SlingJakartaHttpServletRequest, java.lang.String)}.
     */
    @Test
    public void testExternalizePath() {
        MockSlingHttpServletRequest request = context.request();
        SlingJakartaHttpServletRequest jakartaRequest = JavaxToJakartaRequestWrapper.toJakartaRequest(request);

        assertNull(taps.externalizePath(jakartaRequest, null));
        assertEquals("/path", taps.externalizePath(jakartaRequest, "/content/path"));
    }

    @Test
    public void testExternalizePathWithAllowNonExistingPaths() {
        MockSlingHttpServletRequest request = context.request();
        SlingJakartaHttpServletRequest jakartaRequest = JavaxToJakartaRequestWrapper.toJakartaRequest(request);

        taps = Mockito.spy(taps);
        Mockito.doReturn(true).when(taps).allowNonExistingPaths();
        assertEquals(PrincipalAceHelper.RESOURCE_PATH_REPOSITORY, taps.externalizePath(jakartaRequest, null));
    }

    @Test
    public void testExternalizePathWithDisplayExtension() {
        MockSlingHttpServletRequest request = context.request();
        SlingJakartaHttpServletRequest jakartaRequest = JavaxToJakartaRequestWrapper.toJakartaRequest(request);

        request.setParameterMap(Map.of(SlingPostConstants.RP_DISPLAY_EXTENSION, "ext"));
        assertEquals("/path.ext", taps.externalizePath(jakartaRequest, "/content/path"));

        request.setParameterMap(Map.of(SlingPostConstants.RP_DISPLAY_EXTENSION, ""));
        assertEquals("/path", taps.externalizePath(jakartaRequest, "/content/path"));

        request.setParameterMap(Map.of(SlingPostConstants.RP_DISPLAY_EXTENSION, ".ext"));
        assertEquals("/path.ext", taps.externalizePath(jakartaRequest, "/content/path"));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.AbstractAccessPostServlet#allowNonExistingPaths()}.
     */
    @Test
    public void testAllowNonExistingPaths() {
        assertFalse(taps.allowNonExistingPaths());
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.AbstractAccessPostServlet#getParentPath(java.lang.String)}.
     */
    @Test
    public void testGetParentPath() {
        assertNull(taps.getParentPath(null));
        assertEquals("/content", taps.getParentPath("/content/path"));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.AbstractAccessPostServlet#getAccessControlList(javax.jcr.security.AccessControlManager, java.lang.String, boolean)}.
     */
    @Test
    public void testGetAccessControlList() throws RepositoryException {
        AccessControlManager acManager = Mockito.mock(AccessControlManager.class);
        Mockito.when(acManager.getPolicies(anyString())).thenReturn(new AccessControlPolicy[0]);
        assertThrows(RepositoryException.class, () -> taps.getAccessControlList(acManager, "/content/node1", false));

        Mockito.when(acManager.getApplicablePolicies(anyString())).thenReturn(AccessControlPolicyIteratorAdapter.EMPTY);
        assertThrows(RepositoryException.class, () -> taps.getAccessControlList(acManager, "/content/node1", true));
    }

    @Test
    public void testGetAccessControlListWithFoundACL() throws RepositoryException {
        AccessControlManager acManager = Mockito.mock(AccessControlManager.class);
        AccessControlPolicy mockNonAcl = Mockito.mock(AccessControlPolicy.class);
        AccessControlList mockAcl = Mockito.mock(AccessControlList.class);
        Mockito.when(acManager.getPolicies(anyString())).thenReturn(new AccessControlPolicy[] {mockNonAcl, mockAcl});
        assertSame(mockAcl, taps.getAccessControlList(acManager, "/content/node1", false));
    }

    @Test
    public void testGetAccessControlListWithCreatedNewACL() throws RepositoryException {
        AccessControlManager acManager = Mockito.mock(AccessControlManager.class);
        AccessControlPolicy mockNonAcl = Mockito.mock(AccessControlPolicy.class);
        AccessControlList mockAcl = Mockito.mock(AccessControlList.class);
        Mockito.when(acManager.getPolicies(anyString())).thenReturn(new AccessControlPolicy[0]);
        Mockito.when(acManager.getApplicablePolicies(anyString()))
                .thenReturn(new AccessControlPolicyIteratorAdapter(List.of(mockNonAcl, mockAcl)));

        assertSame(mockAcl, taps.getAccessControlList(acManager, "/content/node1", true));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.AbstractAccessPostServlet#getAccessControlListOrNull(javax.jcr.security.AccessControlManager, java.lang.String, boolean)}.
     */
    @Test
    public void testGetAccessControlListOrNull() throws RepositoryException {
        AccessControlManager acManager = Mockito.mock(AccessControlManager.class);
        Mockito.when(acManager.getPolicies(anyString())).thenReturn(new AccessControlPolicy[0]);
        assertNull(taps.getAccessControlListOrNull(acManager, "/content/node1", false));

        Mockito.when(acManager.getApplicablePolicies(anyString())).thenReturn(AccessControlPolicyIteratorAdapter.EMPTY);
        assertNull(taps.getAccessControlListOrNull(acManager, "/content/node1", true));
    }

    @Test
    public void testGetAccessControlListOrNullWithFoundACL() throws RepositoryException {
        AccessControlManager acManager = Mockito.mock(AccessControlManager.class);
        AccessControlPolicy mockNonAcl = Mockito.mock(AccessControlPolicy.class);
        AccessControlList mockAcl = Mockito.mock(AccessControlList.class);
        Mockito.when(acManager.getPolicies(anyString())).thenReturn(new AccessControlPolicy[] {mockNonAcl, mockAcl});
        assertSame(mockAcl, taps.getAccessControlListOrNull(acManager, "/content/node1", false));
    }

    @Test
    public void testGetAccessControlListOrNullWithCreatedNewACL() throws RepositoryException {
        AccessControlManager acManager = Mockito.mock(AccessControlManager.class);
        AccessControlPolicy mockNonAcl = Mockito.mock(AccessControlPolicy.class);
        AccessControlList mockAcl = Mockito.mock(AccessControlList.class);
        Mockito.when(acManager.getPolicies(anyString())).thenReturn(new AccessControlPolicy[0]);
        Mockito.when(acManager.getApplicablePolicies(anyString()))
                .thenReturn(new AccessControlPolicyIteratorAdapter(List.of(mockNonAcl, mockAcl)));

        assertSame(mockAcl, taps.getAccessControlListOrNull(acManager, "/content/node1", true));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.AbstractAccessPostServlet#bindPostResponseCreator(org.apache.sling.servlets.post.JakartaPostResponseCreator, java.util.Map)}.
     */
    @Test
    public void testBindPostResponseCreator() {
        MockSlingHttpServletRequest request = context.request();
        SlingJakartaHttpServletRequest jakartaRequest = JavaxToJakartaRequestWrapper.toJakartaRequest(request);

        JakartaPostResponseCreator mockCreator1 = Mockito.mock(JakartaPostResponseCreator.class);
        taps.bindPostResponseCreator(mockCreator1, Map.of(Constants.SERVICE_RANKING, 1));

        JakartaPostResponse mockPostResponse1 = Mockito.mock(JakartaPostResponse.class);
        Mockito.when(mockCreator1.createPostResponse(jakartaRequest)).thenReturn(mockPostResponse1);
        assertEquals(mockPostResponse1, taps.createPostResponse(jakartaRequest));

        JakartaPostResponseCreator mockCreator3 = Mockito.mock(JakartaPostResponseCreator.class);
        taps.bindPostResponseCreator(mockCreator3, Map.of(Constants.SERVICE_RANKING, 3));

        JakartaPostResponse mockPostResponse3 = Mockito.mock(JakartaPostResponse.class);
        Mockito.when(mockCreator3.createPostResponse(jakartaRequest)).thenReturn(mockPostResponse3);
        assertEquals(mockPostResponse3, taps.createPostResponse(jakartaRequest));

        JakartaPostResponseCreator mockCreator2 = Mockito.mock(JakartaPostResponseCreator.class);
        taps.bindPostResponseCreator(mockCreator2, Map.of(Constants.SERVICE_RANKING, 2));
        assertEquals(mockPostResponse3, taps.createPostResponse(jakartaRequest));
    }

    /**
     * Test method for {@link org.apache.sling.jcr.jackrabbit.accessmanager.post.AbstractAccessPostServlet#unbindPostResponseCreator(org.apache.sling.servlets.post.JakartaPostResponseCreator, java.util.Map)}.
     */
    @Test
    public void testUnbindPostResponseCreator() {
        MockSlingHttpServletRequest request = context.request();
        SlingJakartaHttpServletRequest jakartaRequest = JavaxToJakartaRequestWrapper.toJakartaRequest(request);

        JakartaPostResponseCreator mockCreator1 = Mockito.mock(JakartaPostResponseCreator.class);
        JakartaPostResponse mockPostResponse1 = Mockito.mock(JakartaPostResponse.class);
        Mockito.when(mockCreator1.createPostResponse(jakartaRequest)).thenReturn(mockPostResponse1);
        Map<String, Object> creatorProps1 = Map.of(Constants.SERVICE_RANKING, 1);
        taps.bindPostResponseCreator(mockCreator1, creatorProps1);
        assertEquals(mockPostResponse1, taps.createPostResponse(jakartaRequest));

        JakartaPostResponseCreator mockCreator2 = Mockito.mock(JakartaPostResponseCreator.class);
        JakartaPostResponse mockPostResponse2 = Mockito.mock(JakartaPostResponse.class);
        Mockito.when(mockCreator2.createPostResponse(jakartaRequest)).thenReturn(mockPostResponse2);
        Map<String, Object> creatorProps2 = Map.of(Constants.SERVICE_RANKING, 1);
        taps.bindPostResponseCreator(mockCreator2, creatorProps2);
        assertEquals(mockPostResponse2, taps.createPostResponse(jakartaRequest));

        taps.unbindPostResponseCreator(mockCreator2, creatorProps1);
        assertEquals(mockPostResponse1, taps.createPostResponse(jakartaRequest));
        taps.unbindPostResponseCreator(mockCreator1, creatorProps2);
        assertTrue(taps.createPostResponse(jakartaRequest) instanceof JakartaHtmlResponse);
    }

    private class TestAccessPostServlet extends AbstractAccessPostServlet {
        private static final long serialVersionUID = -2948341218853558959L;

        @Override
        protected void handleOperation(
                SlingJakartaHttpServletRequest request, JakartaPostResponse response, List<Modification> changes)
                throws RepositoryException {
            // do nothing
        }
    }
}
