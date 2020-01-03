package com.amazon.opendistroforelasticsearch.security.ssl.rest;

import com.amazon.opendistroforelasticsearch.security.ssl.DefaultOpenDistroSecurityKeyStore;
import com.amazon.opendistroforelasticsearch.security.ssl.OpenDistroSecurityKeyStore;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.ssl.util.ChannelAnalyzer;
import io.netty.buffer.PooledByteBufAllocator;
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

import javax.net.ssl.SSLEngine;
import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
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

                try {
                    // Update the certificate
                    odsks.UpdateCertificates();

                    // Read the certificate locally to make sure it's up to date.
                    DefaultOpenDistroSecurityKeyStore ks = (DefaultOpenDistroSecurityKeyStore) odsks;
                    SSLEngine engine = ks.transportServerSslContext.newEngine(PooledByteBufAllocator.DEFAULT);

                    Certificate[] localCertsFromEngine = engine.getSession().getLocalCertificates();
                    X509Certificate[] localCerts = Arrays.stream(localCertsFromEngine).filter(s -> s instanceof X509Certificate).toArray(X509Certificate[]::new);
                    builder.startObject();
                    builder.field("updated_local_certificates_list", localCerts == null?null:Arrays.stream(localCerts).map(c->c.getSubjectDN().getName()).collect(Collectors.toList()));
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

