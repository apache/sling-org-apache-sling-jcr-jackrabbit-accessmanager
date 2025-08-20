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

import java.io.IOException;

import jakarta.servlet.http.HttpServletResponse;
import org.apache.sling.api.SlingJakartaHttpServletRequest;
import org.apache.sling.servlets.post.AbstractJakartaPostResponse;
import org.apache.sling.servlets.post.JakartaPostResponse;
import org.apache.sling.servlets.post.JakartaPostResponseCreator;

/**
 * Sample implementation of the PostResponseCreator interface.
 */
public class CustomPostResponseCreatorImpl implements JakartaPostResponseCreator {

    public JakartaPostResponse createPostResponse(SlingJakartaHttpServletRequest req) {
        if ("custom".equals(req.getParameter(":responseType"))) {
            return new AbstractJakartaPostResponse() {

                public void onChange(String type, String... arguments) {
                    // NO-OP
                }

                @Override
                protected void doSend(HttpServletResponse response) throws IOException {
                    response.setContentType("text/html");
                    response.setCharacterEncoding("UTF-8");

                    response.getWriter().write("Thanks!");
                    response.getWriter().flush();
                }
            };
        } else {
            return null;
        }
    }
}
