package com.amazon.opendistroforelasticsearch.security.ssl.rest;


import org.elasticsearch.transport.netty4.Netty4TcpChannel;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ChannelAnalyzer {
    private static ChannelAnalyzer channelAnalyzerInstance = null;
    public final Map<String, Netty4TcpChannel> contextMap = new ConcurrentHashMap<String, Netty4TcpChannel>();
    public static ChannelAnalyzer getChannelAnalyzerInstance() {
                if(channelAnalyzerInstance == null) {
                        channelAnalyzerInstance = new ChannelAnalyzer();
                    }
                return channelAnalyzerInstance;
            }

        public long getActiveElements() {
                return contextMap.entrySet().stream().filter(a->a.getValue().getLowLevelChannel().isActive()).count();
            }

        public long getElements() {
                return contextMap.size();
            }

        public void addToList(String key, NettyTcpChannel channel) {
                contextMap.putIfAbsent(key, channel);
            }
}