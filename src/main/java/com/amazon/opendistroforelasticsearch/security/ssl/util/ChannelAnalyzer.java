package com.amazon.opendistroforelasticsearch.security.ssl.util;

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
        return contextMap.entrySet().stream().filter(a->a.getValue().getNettyChannel().isActive()).count();
    }

    public long getElements() {
        return contextMap.size();
    }

    public void addToList(String key, Netty4TcpChannel channel) {
        contextMap.putIfAbsent(key, channel);
    }

    public void removeFromList(String key) {
        if (contextMap.containsKey(key)) {
            contextMap.remove(key);
        }
    }
}