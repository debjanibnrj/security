package com.amazon.opendistroforelasticsearch.security.session;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ResourceAlreadyExistsException;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.health.ClusterHealthStatus;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Map;

public class SessionRepository {

    private static final Logger LOGGER = LogManager.getLogger(SessionRepository.class);
    private final String opendistroSessionIndex;
    private final Settings settings;
    private final Client client;
    private final ThreadPool threadPool;
    private final ClusterService clusterService;
    private final AuditLog auditLog;
    private final ArrayList<Object> sessionChangedListener;
    private final Cache<Object, Object> securityConfigCache;
    private final Thread bgThread;

    private SessionRepository(Settings settings, final Path configPath, ThreadPool threadPool,
                              Client client, ClusterService clusterService, AuditLog auditLog) {
        this.opendistroSessionIndex = settings.get(ConfigConstants.OPENDISTRO_SECURITY_SESSION_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_SESSION_INDEX);
        this.settings = settings;
        this.client = client;
        this.threadPool = threadPool;
        this.clusterService = clusterService;
        this.auditLog = auditLog;
        this.sessionChangedListener = new ArrayList<>();
        // cl = new ConfigurationLoaderSecurity7(client, threadPool, settings, clusterService);

        securityConfigCache = CacheBuilder
            .newBuilder()
            .build();

        bgThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    createSessionIndexIfAbsent();
//                            } else {
//
                    LOGGER.debug("Node started, try to initialize it. Wait for at least yellow cluster state....");
                    ClusterHealthResponse response = null;
                    try {
                        response = client.admin().cluster().health(new ClusterHealthRequest(opendistroSessionIndex)
                            .waitForActiveShards(1)
                            .waitForYellowStatus()).actionGet();
                    } catch (Exception e1) {
                        LOGGER.debug("Catched a {} but we just try again ...", e1.toString());
                    }
//
                    while(response == null || response.isTimedOut() || response.getStatus() == ClusterHealthStatus.RED) {
                        LOGGER.debug("index '{}' not healthy yet, we try again ... (Reason: {})", opendistroSessionIndex, response==null?"no response":(response.isTimedOut()?"timeout":"other, maybe red cluster"));
                        try {
                            Thread.sleep(500);
                        } catch (InterruptedException e1) {
                            //ignore
                            Thread.currentThread().interrupt();
                        }
                        try {
                            response = client.admin().cluster().health(new ClusterHealthRequest(opendistroSessionIndex).waitForYellowStatus()).actionGet();
                        } catch (Exception e1) {
                            LOGGER.debug("Catched again a {} but we just try again ...", e1.toString());
                        }
                        continue;
                    }
//
//                    while(!dynamicConfigFactory.isInitialized()) {
//                        try {
//                            LOGGER.debug("Try to load config ...");
//                            reloadConfiguration(Arrays.asList(CType.values()));
//                            break;
//                        } catch (Exception e) {
//                            LOGGER.debug("Unable to load configuration due to {}", String.valueOf(ExceptionUtils.getRootCause(e)));
//                            try {
//                                Thread.sleep(3000);
//                            } catch (InterruptedException e1) {
//                                Thread.currentThread().interrupt();
//                                LOGGER.debug("Thread was interrupted so we cancel initialization");
//                                break;
//                            }
//                        }
//                    }
//
//                    final Set<String> deprecatedAuditKeysInSettings = AuditConfig.getDeprecatedKeys(settings);
//                    if (!deprecatedAuditKeysInSettings.isEmpty()) {
//                        LOGGER.warn("Following keys {} are deprecated in elasticsearch settings. They will be removed in plugin v2.0.0.0", deprecatedAuditKeysInSettings);
//                    }
//                    final boolean isAuditConfigDocPresentInIndex = cl.isAuditConfigDocPresentInIndex();
//                    if (isAuditConfigDocPresentInIndex) {
//                        if (!deprecatedAuditKeysInSettings.isEmpty()) {
//                            LOGGER.warn("Audit configuration settings found in both index and elasticsearch settings (deprecated)");
//                        }
//                        LOGGER.info("Hot-reloading of audit configuration is enabled");
//                    } else {
//                        LOGGER.info("Hot-reloading of audit configuration is disabled. Using configuration with defaults from elasticsearch settings.  Populate the configuration in index using audit.yml or securityadmin to enable it.");
//                        auditLog.setConfig(AuditConfig.from(settings));
//                    }
//
//                    LOGGER.info("Node '{}' initialized", clusterService.localNode().getName());

                } catch (Exception e) {
                    LOGGER.error("Unexpected exception while initializing node "+e, e);
                }
            }
        });
    }

    public static SessionRepository create(Settings settings, final Path configPath, final ThreadPool threadPool,
                                                 Client client,  ClusterService clusterService, AuditLog auditLog) {

        SessionRepository repository = new SessionRepository(settings, configPath, threadPool, client, clusterService, auditLog);
        return repository;
    }

    private boolean createSessionIndexIfAbsent() {
        try {
            final Map<String, Object> indexSettings = ImmutableMap.of(
                "index.number_of_shards", 1,
                "index.auto_expand_replicas", "0-all"
            );
            final CreateIndexRequest createIndexRequest = new CreateIndexRequest(opendistroSessionIndex)
                .settings(indexSettings);
            final boolean ok = client.admin()
                .indices()
                .create(createIndexRequest)
                .actionGet()
                .isAcknowledged();
            LOGGER.info("Index {} created?: {}", opendistroSessionIndex, ok);
            return ok;
        } catch (ResourceAlreadyExistsException resourceAlreadyExistsException) {
            LOGGER.info("Index {} already exists", opendistroSessionIndex);
            return false;
        }
    }

} 
