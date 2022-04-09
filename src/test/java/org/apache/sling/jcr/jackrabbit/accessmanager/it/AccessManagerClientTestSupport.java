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

import static org.apache.sling.testing.paxexam.SlingOptions.slingCommonsCompiler;
import static org.apache.sling.testing.paxexam.SlingOptions.slingJcrJackrabbitSecurity;
import static org.apache.sling.testing.paxexam.SlingOptions.slingScriptingJavascript;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.ops4j.pax.exam.CoreOptions.when;
import static org.ops4j.pax.exam.cm.ConfigurationAdminOptions.factoryConfiguration;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Dictionary;
import java.util.List;

import javax.inject.Inject;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonValue;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.NameValuePair;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.junit.After;
import org.junit.Before;
import org.ops4j.pax.exam.Option;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;

/**
 * base class for tests doing http requests to verify calls to the accessmanager
 * servlets
 */
public abstract class AccessManagerClientTestSupport extends AccessManagerTestSupport {
    protected static final int SC_UNPROCESSABLE_ENTITY = 422; // http status code for 422 Unprocessable Entity

    protected static final String TEST_FOLDER_JSON = "{'jcr:primaryType': 'nt:unstructured'}";

    protected static final String CONTENT_TYPE_JSON = "application/json";
    protected static final String CONTENT_TYPE_HTML = "text/html";

    protected static long randomId = System.currentTimeMillis();

    protected static synchronized long getNextInt() {
        final long val = randomId;
        randomId++;
        return val;
    }

    @Inject
    protected ConfigurationAdmin cm;

    protected static final String COOKIE_SLING_FORMAUTH = "sling.formauth";
    protected static final String COOKIE_SLING_FORMAUTH_DOMAIN = "sling.formauth.cookie.domain";
    protected static final String HEADER_SET_COOKIE = "Set-Cookie";

    protected URI baseServerUri;
    protected HttpClientContext httpContext;
    protected CloseableHttpClient httpClient;

    protected String testUserId = null;
    protected String testUserId2 = null;
    protected String testGroupId = null;
    protected String testFolderUrl = null;

    @Override
    protected Option[] additionalOptions() throws IOException {
        // optionally create a tinybundle that contains a test script
        final Option bundle = buildBundleResourcesBundle();

        return new Option[]{
            // for usermanager support
            slingJcrJackrabbitSecurity(),
            // add javascript support for the test script
            slingCommonsCompiler(),
            when(bundle != null).useOptions(slingScriptingJavascript()),

            // add the test script tinybundle
            when(bundle != null).useOptions(bundle),

            // enable the healthcheck configuration for checking when the server is ready to
            //  receive http requests.  (adapted from the starter healthcheck.json configuration)
            factoryConfiguration("org.apache.felix.hc.generalchecks.FrameworkStartCheck")
                .put("hc.tags", new String[] {"systemalive"})
                .put("targetStartLevel", 5)
                .asOption(),
            factoryConfiguration("org.apache.felix.hc.generalchecks.ServicesCheck")
                .put("hc.tags", new String[] {"systemalive"})
                .put("services.list", new String[] {
                        "org.apache.sling.jcr.api.SlingRepository",
                        "org.apache.sling.engine.auth.Authenticator",
                        "org.apache.sling.api.resource.ResourceResolverFactory",
                        "org.apache.sling.api.servlets.ServletResolver",
                        "javax.script.ScriptEngineManager"
                })
                .asOption(),
            factoryConfiguration("org.apache.felix.hc.generalchecks.BundlesStartedCheck")
                .put("hc.tags", new String[] {"bundles"})
                .asOption(),
            factoryConfiguration("org.apache.sling.jcr.contentloader.hc.BundleContentLoadedCheck")
                .put("hc.tags", new String[] {"bundles"})
                .asOption(),
        };
    }

    @Before
    public void before() throws IOException, URISyntaxException {
        // wait for the health checks to be OK
        waitForServerReady(Duration.ofMinutes(1).toMillis(), 500);

        // calculate the address of the http server
        baseServerUri = getBaseServerUri();
        assertNotNull(baseServerUri);

        HttpHost targetHost = new HttpHost(baseServerUri.getHost(), baseServerUri.getPort(), baseServerUri.getScheme());
        AuthCache authCache = new BasicAuthCache();
        authCache.put(targetHost, new BasicScheme());

        // prepare the http client for the test user
        httpContext = HttpClientContext.create();
        httpContext.setCookieStore(new BasicCookieStore());
        httpContext.setCredentialsProvider(new BasicCredentialsProvider());
        httpContext.setAuthCache(authCache);
        RequestConfig requestConfig = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD_STRICT).build();
        httpContext.setRequestConfig(requestConfig);
        httpClient = HttpClients.custom()
                .disableRedirectHandling()
                .build();
    }

    @After
    public void after() throws IOException {
        Credentials creds = new UsernamePasswordCredentials("admin", "admin");

        if (testFolderUrl != null) {
            //remove the test user if it exists.
            List<NameValuePair> postParams = new ArrayList<>();
            postParams.add(new BasicNameValuePair(":operation", "delete"));
            assertAuthenticatedPostStatus(creds, testFolderUrl, HttpServletResponse.SC_OK, postParams, null);
        }
        if (testGroupId != null) {
            //remove the test user if it exists.
            String postUrl = String.format("%s/system/userManager/group/%s.delete.html", baseServerUri, testGroupId);
            assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, Collections.emptyList(), null);
        }
        if (testUserId != null) {
            //remove the test user if it exists.
            String postUrl = String.format("%s/system/userManager/user/%s.delete.html", baseServerUri, testUserId);
            assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, Collections.emptyList(), null);
        }
        if (testUserId2 != null) {
            //remove the test user if it exists.
            String postUrl = String.format("%s/system/userManager/user/%s.delete.html", baseServerUri, testUserId2);
            assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, Collections.emptyList(), null);
        }

        // close/cleanup the test user http client
        if (httpClient != null) {
            httpClient.close();
            httpClient = null;
        }

        // clear out other state
        httpContext = null;
        baseServerUri = null;
    }

    /**
     * Calculate the base server URI from the current configuration of the
     * httpservice
     */
    protected URI getBaseServerUri() throws IOException, URISyntaxException {
        assertNotNull(cm);
        Configuration httpServiceConfiguration = cm.getConfiguration("org.apache.felix.http");
        Dictionary<String, Object> properties = httpServiceConfiguration.getProperties();

        String host;
        Object hostObj = properties.get("org.apache.felix.http.host");
        if (hostObj == null) {
            host = "localhost";
        } else {
            assertTrue(hostObj instanceof String);
            host = (String)hostObj;
        }
        assertNotNull(host);

        String scheme = null;
        Object portObj = null;
        Object httpsEnableObj = properties.get("org.apache.felix.https.enable");
        if ("true".equals(httpsEnableObj)) {
            scheme = "https";
            portObj = properties.get("org.osgi.service.http.port.secure");
        } else {
            Object httpEnableObj = properties.get("org.apache.felix.http.enable");
            if (httpEnableObj == null || "true".equals(httpEnableObj)) {
                scheme = "http";
                portObj = properties.get("org.osgi.service.http.port");
            } else {
                fail("Expected either http or https to be enabled");
            }
        }
        int port = -1;
        if (portObj instanceof Number) {
            port = ((Number)portObj).intValue();
        }
        assertTrue(port > 0);

        return new URI(String.format("%s://%s:%d", scheme, host, port));
    }

    protected void assertPrivilege(Collection<String> privileges, boolean expected, String privilegeName) {
        if(expected != privileges.contains(privilegeName)) {
            fail("Expected privilege " + privilegeName + " to be "
                    + (expected ? "included" : "NOT INCLUDED")
                    + " in supplied list: " + privileges + ")");
        }
    }

    protected void assertPrivilege(JsonObject privilegesObject, boolean expected, boolean allow, String privilegeName) {
        assertPrivilege(privilegesObject, expected, allow, privilegeName, null);
    }
    protected void assertPrivilege(JsonObject privilegesObject, boolean expected, boolean allow, String privilegeName,
            VerifyAce verifyAce) {
        assertNotNull(privilegesObject);
        if (expected != privilegesObject.containsKey(privilegeName)) {
            fail("Expected privilege " + privilegeName + " to be "
                    + (expected ? "included" : "NOT INCLUDED")
                    + " in supplied object)");
        }
        JsonObject privilegeObj = privilegesObject.getJsonObject(privilegeName);
        if (!expected) {
            assertNull(privilegeObj);
        } else {
            assertNotNull(privilegeObj);
            String key;
            if (allow) {
                key = "allow";
            } else {
                key = "deny";
            }
            assertTrue(privilegeObj.containsKey(key));
            JsonValue jsonValue = privilegeObj.get(key);
            if (verifyAce != null) {
                verifyAce.verify(jsonValue);
            }
        }
    }

    protected Object doAuthenticatedWork(Credentials creds, AuthenticatedWorker worker) throws IOException {
        Object result = null;
        AuthScope authScope = new AuthScope(baseServerUri.getHost(), baseServerUri.getPort(), baseServerUri.getScheme());
        CredentialsProvider oldCredentialsProvider = httpContext.getCredentialsProvider();
        try {
            BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
            httpContext.setCredentialsProvider(credentialsProvider);
            credentialsProvider.setCredentials(authScope, creds);

            result = worker.doWork();
        } finally {
            httpContext.setCredentialsProvider(oldCredentialsProvider);
        }
        return result;
    }

    protected void assertAuthenticatedPostStatus(Credentials creds, String url, int expectedStatusCode, List<NameValuePair> postParams, String assertMessage) throws IOException {
        doAuthenticatedWork(creds, () -> {
            HttpPost postRequest = new HttpPost(url);
            postRequest.setEntity(new UrlEncodedFormEntity(postParams));
            try (CloseableHttpResponse response = httpClient.execute(postRequest, httpContext)) {
                assertEquals(assertMessage, expectedStatusCode, response.getStatusLine().getStatusCode());
            }
            return null;
        });
    }

    protected void assertAuthenticatedHttpStatus(Credentials creds, String urlString, int expectedStatusCode, String assertMessage) throws IOException {
        doAuthenticatedWork(creds, () -> {
            HttpGet getRequest = new HttpGet(urlString);
            try (CloseableHttpResponse response = httpClient.execute(getRequest, httpContext)) {
                assertEquals(assertMessage, expectedStatusCode, response.getStatusLine().getStatusCode());
                return null;
            }
        });
    }

    protected String getAuthenticatedContent(Credentials creds, String url, String expectedContentType, int expectedStatusCode) throws IOException {
        return (String)doAuthenticatedWork(creds, () -> {
            HttpGet getRequest = new HttpGet(url);
            try (CloseableHttpResponse response = httpClient.execute(getRequest, httpContext)) {
                assertEquals(expectedStatusCode, response.getStatusLine().getStatusCode());
                final Header h = response.getFirstHeader("Content-Type");
                if (expectedContentType == null) {
                    if (h != null) {
                        fail("Expected null Content-Type, got " + h.getValue());
                    }
                } else if (h == null) {
                    fail(
                            "Expected Content-Type that starts with '" + expectedContentType
                            +" but got no Content-Type header at " + url
                    );
                } else {
                    assertTrue(
                        "Expected Content-Type that starts with '" + expectedContentType
                        + "' for " + url + ", got '" + h.getValue() + "'",
                        h.getValue().startsWith(expectedContentType)
                    );
                }
                return EntityUtils.toString(response.getEntity());
            }
        });
    }

    protected String getAuthenticatedPostContent(Credentials creds, String url, String expectedContentType, List<NameValuePair> postParams, int expectedStatusCode) throws IOException {
        return (String)doAuthenticatedWork(creds, () -> {
            HttpPost postRequest = new HttpPost(url);
            postRequest.setEntity(new UrlEncodedFormEntity(postParams));
            try (CloseableHttpResponse response = httpClient.execute(postRequest, httpContext)) {
                assertEquals(expectedStatusCode, response.getStatusLine().getStatusCode());
                final Header h = response.getFirstHeader("Content-Type");
                if (expectedContentType == null) {
                    if (h != null) {
                        fail("Expected null Content-Type, got " + h.getValue());
                    }
                } else if (h == null) {
                    fail(
                            "Expected Content-Type that starts with '" + expectedContentType
                            +" but got no Content-Type header at " + url
                    );
                } else {
                    assertTrue(
                        "Expected Content-Type that starts with '" + expectedContentType
                        + "' for " + url + ", got '" + h.getValue() + "'",
                        h.getValue().startsWith(expectedContentType)
                    );
                }
                return EntityUtils.toString(response.getEntity());
            }
        });
    }

    protected String createTestUser() throws IOException {
        String postUrl = String.format("%s/system/userManager/user.create.html", baseServerUri);

        String userId = "testUser" + getNextInt();
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":name", userId));
        postParams.add(new BasicNameValuePair("pwd", "testPwd"));
        postParams.add(new BasicNameValuePair("pwdConfirm", "testPwd"));
        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        final String msg = "Unexpected status while attempting to create test user at " + postUrl;
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, msg);

        final String sessionInfoUrl = String.format("%s/system/sling/info.sessionInfo.json", baseServerUri);
        assertAuthenticatedHttpStatus(creds, sessionInfoUrl, HttpServletResponse.SC_OK,
                "session info failed for user " + userId);

        return userId;
    }

    protected String createTestGroup() throws IOException {
        String postUrl = String.format("%s/system/userManager/group.create.html", baseServerUri);

        String groupId = "testGroup" + getNextInt();
        List<NameValuePair> postParams = new ArrayList<>();
        postParams.add(new BasicNameValuePair(":name", groupId));

        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        final String msg = "Unexpected status while attempting to create test group at " + postUrl;
        assertAuthenticatedPostStatus(creds, postUrl, HttpServletResponse.SC_OK, postParams, msg);

        return groupId;
    }

    protected String createTestFolder() throws IOException {
        return createTestFolder(null, "sling-tests");
    }

    protected String createTestFolder(String parentPath, String nameHint) throws IOException {
        return createTestFolder(parentPath, nameHint, TEST_FOLDER_JSON);
    }
    protected String createTestFolder(String parentPath, String nameHint, String jsonImport) throws IOException {
        JsonObject json = importJSON(parentPath, nameHint, jsonImport);
        return String.format("%s%s", baseServerUri, json.getString("path"));
    }

    protected JsonObject importJSON(String nameHint, String jsonImport) throws IOException {
        return importJSON(null, nameHint, jsonImport);
    }

    protected JsonObject importJSON(String parentPath, String nameHint, String jsonImport) throws IOException {
        JsonObject result = null;
        Credentials creds = new UsernamePasswordCredentials("admin", "admin");
        result = (JsonObject)doAuthenticatedWork(creds, () -> {
            List<NameValuePair> parameters = new ArrayList<>();
            parameters.add(new BasicNameValuePair(":operation", "import"));
            if (nameHint != null) {
                parameters.add(new BasicNameValuePair(":nameHint", nameHint));
            }
            parameters.add(new BasicNameValuePair(":content", jsonImport));
            parameters.add(new BasicNameValuePair(":contentType", "json"));
            parameters.add(new BasicNameValuePair(":replaceProperties", "true"));

            String postUrl = String.format("%s%s", baseServerUri, parentPath != null ? parentPath : "/content");
            HttpPost postRequest = new HttpPost(postUrl);
            postRequest.setEntity(new UrlEncodedFormEntity(parameters));
            postRequest.addHeader(new BasicHeader("Accept", "application/json,*/*;q=0.9"));
            JsonObject jsonObj = null;
            try (CloseableHttpResponse response = httpClient.execute(postRequest, httpContext)) {
                assertEquals(HttpServletResponse.SC_CREATED, response.getStatusLine().getStatusCode());
                jsonObj = parseJson(EntityUtils.toString(response.getEntity()));
            }
            return jsonObj;
        });
        return result;
    }

    /**
     * @param json the json string to parse
     * @return the parsed JsonObject
     */
    protected JsonObject parseJson(String json) {
        JsonObject jsonObj = null;
        try (JsonReader reader = Json.createReader(new StringReader(json))) {
            jsonObj = reader.readObject();
        }
        return jsonObj;
    }

    protected static interface AuthenticatedWorker {
        public Object doWork() throws IOException;
    }

    protected static interface VerifyAce {
        public void verify(JsonValue jsonValue);
    }

}
