package com.amazon.opendistroforelasticsearch.security.ssl.rest;

import com.amazon.opendistroforelasticsearch.security.ssl.DefaultOpenDistroSecurityKeyStore;
import com.amazon.opendistroforelasticsearch.security.ssl.OpenDistroSecurityKeyStore;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.ssl.util.ChannelAnalyzer;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.ssl.SslHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.transport.netty4.Netty4TcpChannel;

import javax.net.ssl.SSLEngine;
import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

import static org.elasticsearch.rest.RestRequest.Method.GET;

public class UpdateSearchGuardCertificatesAction extends BaseRestHandler {

    private final OpenDistroSecurityKeyStore odsks;
    final PrincipalExtractor principalExtractor;
    private final Path configPath;
    public ChannelAnalyzer channelAnalyzer;
    protected final Logger logger = LogManager.getLogger(this.getClass());

    public UpdateSearchGuardCertificatesAction(final Settings settings, final Path configPath, final RestController controller,
                                               final OpenDistroSecurityKeyStore odsks, final PrincipalExtractor principalExtractor) {
        super(settings);
        this.odsks = odsks;
        this.principalExtractor = principalExtractor;
        this.configPath = configPath;
        this.channelAnalyzer = ChannelAnalyzer.getChannelAnalyzerInstance();
        controller.registerHandler(GET, "/_opendistro/_security/update", this);
    }

    @Override
    public String getName() {
        return "Update Search Guard Certificates";
    }



    @Override
    protected RestChannelConsumer prepareRequest(RestRequest restRequest, NodeClient nodeClient) throws IOException {
        return new RestChannelConsumer() {
            @Override
            public void accept(RestChannel channel) throws Exception {
                XContentBuilder builder = channel.newBuilder();
                BytesRestResponse response = null;
                builder.startObject();
                try {
                    // Update the certificate
                    odsks.UpdateCertificates();

                    DefaultOpenDistroSecurityKeyStore ks = (DefaultOpenDistroSecurityKeyStore) odsks;
                    Map<String, Netty4TcpChannel> map = channelAnalyzer.contextMap;

                    for (Netty4TcpChannel nettyChannel : map.values()) {
                        ChannelPipeline pipeline = nettyChannel.getNettyChannel().pipeline();
                        final SslHandler sslhandler = (SslHandler) pipeline.get("ssl_server");
                        logger.info("Logging SSLHandler is {}", sslhandler);
                    }
                    SSLEngine engine = odsks.createServerTransportSSLEngine();
                    for (Netty4TcpChannel nettyChannel : map.values()) {

                        ChannelPipeline pipeline = nettyChannel.getNettyChannel().pipeline();
                        final SslHandler sslhandler = (SslHandler) pipeline.get("ssl_server");

                        if (sslhandler != null) {
                            SslHandler newSSLHandler = new SslHandler(engine);
                            logger.info("SSLHandler is {}", sslhandler);

                            // Option 1: replace the handler
                            pipeline.replace(sslhandler, "ssl_server", newSSLHandler);

                            // Option 2 (TBD): close the previous one then replace it.


                            Certificate[] localCertsFromEngine = engine.getSession().getLocalCertificates();
                            logger.info("localCertsFromEngine have length {}", localCertsFromEngine == null ? 0: localCertsFromEngine.length);
                            if (localCertsFromEngine != null) {
                                X509Certificate[] localCerts = Arrays.stream(localCertsFromEngine).filter(s -> s instanceof X509Certificate).toArray(X509Certificate[]::new);
                                builder.field("updated_local_certificates_list_for_"+nettyChannel.getNettyChannel().id().toString(), localCerts == null?null:
                                    Arrays.stream(localCerts).map(c->c.getSubjectDN().getName()).collect(Collectors.toList()));
                            }  else {
                                builder.field("unable_for", nettyChannel.getNettyChannel().id().toString());
                            }
                        }


                    }

                    // Read the certificate locally to make sure it's up to date.
                    builder.endObject();
                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (final Exception ex) {
                    builder = channel.newBuilder();
                    builder.startObject();
                    builder.field("error", ex.toString());
                    builder.endObject();
                    response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
                    logger.error("Error handle request ", ex);
                } finally {
                    if(builder != null) {
                        builder.close();
                    }
                }
                channel.sendResponse(response);
            }

        };

        }
}

