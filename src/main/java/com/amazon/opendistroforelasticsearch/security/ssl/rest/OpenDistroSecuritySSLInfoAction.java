/*
 * Copyright 2015-2017 floragunn GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.amazon.opendistroforelasticsearch.security.ssl.rest;

import static org.elasticsearch.rest.RestRequest.Method.GET;

import com.amazon.opendistroforelasticsearch.security.ssl.DefaultOpenDistroSecurityKeyStore;
import com.amazon.opendistroforelasticsearch.security.ssl.util.ChannelAnalyzer;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.handler.ssl.OpenSsl;

import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

import com.amazon.opendistroforelasticsearch.security.ssl.OpenDistroSecurityKeyStore;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLRequestHelper;
import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLRequestHelper.SSLInfo;

import javax.net.ssl.SSLEngine;

public class OpenDistroSecuritySSLInfoAction extends BaseRestHandler {

    private final Logger log = LogManager.getLogger(this.getClass());
    private final OpenDistroSecurityKeyStore odsks;
    final PrincipalExtractor principalExtractor;
    private final Path configPath;
    private final Settings settings;
    public ChannelAnalyzer channelAnalyzer;

    public OpenDistroSecuritySSLInfoAction(final Settings settings, final Path configPath, final RestController controller,
            final OpenDistroSecurityKeyStore odsks, final PrincipalExtractor principalExtractor) {
        super(settings);
        this.settings = settings;
        this.odsks = odsks;
        this.principalExtractor = principalExtractor;
        this.configPath = configPath;
        this.channelAnalyzer = ChannelAnalyzer.getChannelAnalyzerInstance();
        controller.registerHandler(GET, "/_opendistro/_security/sslinfo", this);
    }
    
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return new RestChannelConsumer() {
            
            final Boolean showDn = request.paramAsBoolean("show_dn", Boolean.FALSE);

            @Override
            public void accept(RestChannel channel) throws Exception {
                DefaultOpenDistroSecurityKeyStore dodsks = (DefaultOpenDistroSecurityKeyStore) odsks;
                SSLEngine engine = dodsks.transportServerSslContext.newEngine(PooledByteBufAllocator.DEFAULT);
                Certificate[] localCertsFromEngine = engine.getSession().getLocalCertificates();

                XContentBuilder builder = channel.newBuilder();
                BytesRestResponse response = null;
                try {
                    log.debug("Channel Analyzer has " + channelAnalyzer.getElements() + " total elements");
                    log.debug("Channel Analyzer has " + channelAnalyzer.getActiveElements() + " active elements");

                    SSLInfo sslInfo = SSLRequestHelper.getSSLInfo(settings, configPath, request, principalExtractor);
                    X509Certificate[] certs = sslInfo == null?null:sslInfo.getX509Certs();
                     // Disabling below because getting a Peer Verified Exception
                     // X509Certificate[] certs = Arrays.stream(peerCertsFromEngine).filter(s -> s instanceof X509Certificate).toArray(X509Certificate[]::new);
                    //X509Certificate[] localCerts = sslInfo == null?null:sslInfo.getLocalCertificates();
                    X509Certificate[] localCerts = Arrays.stream(localCertsFromEngine).filter(s -> s instanceof X509Certificate).toArray(X509Certificate[]::new);

                    builder.startObject();

                    //builder.field("principal", sslInfo == null?null:sslInfo.getPrincipal());
                    //builder.field("peer_certificates", certs != null && certs.length > 0 ? certs.length + "" : "0");

                    if(showDn == Boolean.TRUE) {
                        builder.field("peer_certificates_list", certs == null?null:Arrays.stream(certs).map(c->c.getSubjectDN().getName()).collect(Collectors.toList()));
                        builder.field("local_certificates_list", localCerts == null?null:Arrays.stream(localCerts).map(c->c.getSubjectDN().getName()).collect(Collectors.toList()));
                        builder.field("not_after", localCerts == null?null:Arrays.stream(localCerts).map(c->c.getNotAfter().toString()).collect(Collectors.toList()));
                        builder.field("not_before", localCerts == null?null:Arrays.stream(localCerts).map(c->c.getNotBefore().toString()).collect(Collectors.toList()));
                        builder.field("local_certificate_version", localCerts == null?null:Arrays.stream(localCerts).map(c->c.getVersion()).collect(Collectors.toList()));
                        builder.field("Total Channels from local node", channelAnalyzer.getElements());
                         builder.field("Active Channels from local node", channelAnalyzer.getActiveElements());
                    }

                    builder.field("ssl_protocol", sslInfo == null?null:sslInfo.getProtocol());
                    builder.field("ssl_cipher", sslInfo == null?null:sslInfo.getCipher());
                    builder.field("ssl_openssl_available", OpenSsl.isAvailable());
                    builder.field("ssl_openssl_version", OpenSsl.version());
                    builder.field("ssl_openssl_version_string", OpenSsl.versionString());
                    Throwable openSslUnavailCause = OpenSsl.unavailabilityCause();
                    builder.field("ssl_openssl_non_available_cause", openSslUnavailCause==null?"":openSslUnavailCause.toString());
                    builder.field("ssl_openssl_supports_key_manager_factory", OpenSsl.supportsKeyManagerFactory());
                    builder.field("ssl_openssl_supports_hostname_validation", OpenSsl.supportsHostnameValidation());
                    builder.field("ssl_provider_http", odsks.getHTTPProviderName());
                    builder.field("ssl_provider_transport_server", odsks.getTransportServerProviderName());
                    builder.field("ssl_provider_transport_client", odsks.getTransportClientProviderName());
                    builder.endObject();

                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (final Exception e1) {
                    log.error("Error handle request "+e1, e1);
                    builder = channel.newBuilder();
                    builder.startObject();
                    builder.field("error", e1.toString());
                    builder.endObject();
                    response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
                } finally {
                    if(builder != null) {
                        builder.close();
                    }
                }
                
                channel.sendResponse(response);
            }
        };
    }

    @Override
    public String getName() {
        return "Open Distro Security SSL Info";
    }
}
