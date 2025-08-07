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
package org.apache.sling.jcr.jackrabbit.accessmanager.it;

import static org.apache.felix.hc.api.FormattingResultLog.msHumanReadable;
import static org.apache.sling.testing.paxexam.SlingOptions.awaitility;
import static org.apache.sling.testing.paxexam.SlingOptions.paxLoggingApi;
import static org.apache.sling.testing.paxexam.SlingOptions.slingQuickstartOakTar;
import static org.apache.sling.testing.paxexam.SlingOptions.versionResolver;
import static org.awaitility.Awaitility.await;
import static org.junit.Assert.assertNotNull;
import static org.ops4j.pax.exam.CoreOptions.composite;
import static org.ops4j.pax.exam.CoreOptions.junitBundles;
import static org.ops4j.pax.exam.CoreOptions.mavenBundle;
import static org.ops4j.pax.exam.CoreOptions.options;
import static org.ops4j.pax.exam.CoreOptions.streamBundle;
import static org.ops4j.pax.exam.CoreOptions.systemProperty;
import static org.ops4j.pax.exam.CoreOptions.vmOption;
import static org.ops4j.pax.exam.CoreOptions.when;
import static org.ops4j.pax.tinybundles.TinyBundles.bndBuilder;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.inject.Inject;

import org.apache.felix.hc.api.Result;
import org.apache.felix.hc.api.ResultLog;
import org.apache.felix.hc.api.execution.HealthCheckExecutionResult;
import org.apache.felix.hc.api.execution.HealthCheckExecutor;
import org.apache.felix.hc.api.execution.HealthCheckSelector;
import org.apache.sling.testing.paxexam.TestSupport;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.ops4j.pax.exam.Configuration;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.options.ModifiableCompositeOption;
import org.ops4j.pax.exam.options.extra.VMOption;
import org.ops4j.pax.tinybundles.TinyBundle;
import org.ops4j.pax.tinybundles.TinyBundles;
import org.osgi.framework.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AccessManagerTestSupport extends TestSupport {
    private static final String BUNDLE_SYMBOLICNAME = "TEST-CONTENT-BUNDLE";
    private static final String SLING_BUNDLE_RESOURCES_HEADER = "Sling-Bundle-Resources";

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    @Inject
    private HealthCheckExecutor hcExecutor;

    @Rule
    public TestRule watcher = new TestWatcher() {

        /* (non-Javadoc)
         * @see org.junit.rules.TestWatcher#starting(org.junit.runner.Description)
         */
        @Override
        protected void starting(Description description) {
            logger.info("Starting test: {}", description.getMethodName());
        }

        /* (non-Javadoc)
         * @see org.junit.rules.TestWatcher#finished(org.junit.runner.Description)
         */
        @Override
        protected void finished(Description description) {
           logger.info("Finished test: {}", description.getMethodName());
        }

    };

    @Configuration
    public Option[] configuration() throws IOException {
        final String vmOpt = System.getProperty("pax.vm.options");
        VMOption vmOption = null;
        if (vmOpt != null && !vmOpt.isEmpty()) {
            vmOption = new VMOption(vmOpt);
        }

        // SLING-12868 - newer version of sling.api and dependencies
        //   may remove at a later date if the superclass includes these versions or later
        versionResolver.setVersionFromProject("org.apache.sling", "org.apache.sling.api");
        versionResolver.setVersion("org.apache.sling", "org.apache.sling.engine", "3.0.0");
        versionResolver.setVersion("org.apache.felix", "org.apache.felix.http.servlet-api", "6.1.0");
        versionResolver.setVersion("org.apache.sling", "org.apache.sling.resourceresolver", "2.0.0");
        versionResolver.setVersion("org.apache.sling", "org.apache.sling.auth.core", "2.0.0");
        versionResolver.setVersion("commons-fileupload", "commons-fileupload", "1.6.0");
        versionResolver.setVersion("org.apache.sling", "org.apache.sling.scripting.spi", "2.0.0");
        versionResolver.setVersion("org.apache.sling", "org.apache.sling.scripting.core", "3.0.0");
        versionResolver.setVersion("org.apache.sling", "org.apache.sling.servlets.resolver", "3.0.0");
        versionResolver.setVersionFromProject("org.apache.sling", "org.apache.sling.servlets.post");

        return options(
            composite(
                super.baseConfiguration(),
                when(vmOption != null).useOptions(vmOption),
                optionalRemoteDebug(),
                slingQuickstart(),
                paxLoggingApi(), // newer version to provide the 2.x version of slf4j
                systemProperty("org.ops4j.pax.logging.DefaultServiceLog.level").value("INFO"),
                testBundle("bundle.filename"),
                // SLING-12868 - begin extra bundles for sling api 3.x
                mavenBundle()
                        .groupId("org.apache.felix")
                        .artifactId("org.apache.felix.http.wrappers")
                        .version("6.1.0"),
                mavenBundle()
                        .groupId("org.apache.sling")
                        .artifactId("org.apache.sling.commons.johnzon")
                        .version("2.0.0"),
                // end extra bundles for sling api 3.x
                junitBundles(),
                awaitility()
            ).add(
                additionalOptions()
            ).remove(
                // remove our bundle under test to avoid duplication
                mavenBundle().groupId("org.apache.sling").artifactId("org.apache.sling.jcr.jackrabbit.accessmanager").version(versionResolver)
            )
        );
    }

    protected Option[] additionalOptions() throws IOException { // NOSONAR
        return new Option[]{};
    }

    protected Option slingQuickstart() {
        final String workingDirectory = workingDirectory();
        final int httpPort = findFreePort();
        return composite(
            slingQuickstartOakTar(workingDirectory, httpPort)
        );
    }

    public String getTestFileUrl(String path) {
        return getClass().getResource(path).toExternalForm();
    }

    /**
     * Optionally configure remote debugging on the port supplied by the "debugPort"
     * system property.
     */
    protected ModifiableCompositeOption optionalRemoteDebug() {
        VMOption option = null;
        String property = System.getProperty("debugPort");
        if (property != null) {
            option = vmOption(String.format("-Xrunjdwp:transport=dt_socket,server=y,suspend=y,address=%s", property));
        }
        return composite(option);
    }

    /**
     * Wait for the health check to be ok
     *
     * @param timeoutMsec the max time to wait for the health check to be ok
     * @param nextIterationDelay the sleep time between the check attempts
     */
    protected void waitForServerReady(long timeoutMsec, long nextIterationDelay) {
        // retry until the exec call returns true and doesn't throw any exception
        await().atMost(timeoutMsec, TimeUnit.MILLISECONDS)
                .pollInterval(nextIterationDelay, TimeUnit.MILLISECONDS)
                .until(this::doHealthCheck);
    }

    /**
     * @return true if health checks are ok
     */
    protected boolean doHealthCheck() throws IOException {
        boolean isOk = true;
        logger.info("Performing health check");
        HealthCheckSelector hcs = HealthCheckSelector.tags("systemalive");
        List<HealthCheckExecutionResult> results = hcExecutor.execute(hcs);
        logger.info("systemalive health check got {} results", results.size());
        isOk &= !results.isEmpty();
        for (final HealthCheckExecutionResult exR : results) {
            final Result r = exR.getHealthCheckResult();
            if (logger.isInfoEnabled()) {
                logger.info("systemalive health check: {}", toHealthCheckResultInfo(exR, false));
            }
            isOk &= r.isOk();
            if (!isOk) {
                break; // found a failure so stop checking further
            }
        }

        if (isOk) {
            hcs = HealthCheckSelector.tags("bundles");
            results = hcExecutor.execute(hcs);
            logger.info("bundles health check got {} results", results.size());
            isOk &= !results.isEmpty();
            for (final HealthCheckExecutionResult exR : results) {
                final Result r = exR.getHealthCheckResult();
                if (logger.isInfoEnabled()) {
                    logger.info("bundles health check: {}", toHealthCheckResultInfo(exR, false));
                }
                isOk &= r.isOk();
                if (!isOk) {
                    break; // found a failure so stop checking further
                }
            }
        }
        return isOk;
    }

    /**
     * Produce a human readable report of the health check results that is suitable for
     * debugging or writing to a log
     */
    protected String toHealthCheckResultInfo(final HealthCheckExecutionResult exResult, final boolean debug)  throws IOException {
        String value = null;
        try (StringWriter resultWriter = new StringWriter(); BufferedWriter writer = new BufferedWriter(resultWriter)) {
            final Result result = exResult.getHealthCheckResult();

            writer.append('"').append(exResult.getHealthCheckMetadata().getTitle()).append('"');
            writer.append(" result is: ").append(result.getStatus().toString());
            writer.newLine();
            writer.append("   Finished: ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(exResult.getFinishedAt()) + " after "
                    + msHumanReadable(exResult.getElapsedTimeInMs()));

            for (final ResultLog.Entry e : result) {
                if (!debug && e.isDebug()) {
                    continue;
                }
                writer.newLine();
                writer.append("   ");
                writer.append(e.getStatus().toString());
                writer.append(' ');
                writer.append(e.getMessage());
                if (e.getException() != null) {
                    writer.append(" ");
                    writer.append(e.getException().toString());
                }
            }
            writer.flush();
            value = resultWriter.toString();
        }
        return value;
    }

    /**
     * Add content to our test bundle
     */
    protected void addContent(final TinyBundle bundle, String resourcePath) throws IOException {
        String pathInBundle = resourcePath;
        resourcePath = "/content" + resourcePath;
        try (final InputStream is = getClass().getResourceAsStream(resourcePath)) {
            assertNotNull("Expecting resource to be found:" + resourcePath, is);
            logger.info("Adding resource to bundle, path={}, resource={}", pathInBundle, resourcePath);
            bundle.addResource(pathInBundle, is);
        }
    }

    /**
     * Override to provide the option for your test
     *
     * @return the tinybundle Option or null if none
     */
    protected Option buildBundleResourcesBundle() throws IOException {
        return null;
    }

    /**
     * Build a test bundle containing the specified bundle resources
     *
     * @param header the value for the {@link #SLING_BUNDLE_RESOURCES_HEADER} header
     * @param content the collection of files to embed in the tinybundle
     * @return the tinybundle Option
     */
    protected Option buildBundleResourcesBundle(final String header, final Collection<String> content) throws IOException {
        final TinyBundle bundle = TinyBundles.bundle();
        bundle.setHeader(Constants.BUNDLE_SYMBOLICNAME, BUNDLE_SYMBOLICNAME);
        bundle.setHeader(SLING_BUNDLE_RESOURCES_HEADER, header);
        bundle.setHeader("Require-Capability", "osgi.extender;filter:=\"(&(osgi.extender=org.apache.sling.bundleresource)(version<=1.1.0)(!(version>=2.0.0)))\"");

        for (final String entry : content) {
            addContent(bundle, entry);
        }
        return streamBundle(
            bundle.build(bndBuilder())
        ).start();
    }

}
