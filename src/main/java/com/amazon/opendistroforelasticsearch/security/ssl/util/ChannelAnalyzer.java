package com.amazon.opendistroforelasticsearch.security.ssl.util;

import io.netty.channel.Channel;
import org.elasticsearch.transport.netty4.Netty4TcpChannel;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ChannelAnalyzer {
    private static ChannelAnalyzer channelAnalyzerInstance = null;
    public final Map<String, Channel> contextMap = new ConcurrentHashMap<String, Channel>();
    public static ChannelAnalyzer getChannelAnalyzerInstance() {
        if(channelAnalyzerInstance == null) {
            channelAnalyzerInstance = new ChannelAnalyzer();
        }
        return channelAnalyzerInstance;
    }

    public long getActiveElements() {
        return contextMap.entrySet().stream().filter(a->a.getValue().isActive()).count();
    }

    public long getElements() {
        return contextMap.size();
    }

    public void addToList(String key, Channel channel) {
        contextMap.putIfAbsent(key, channel);
    }

    public void addToList(String key, Netty4TcpChannel channel) {
        addToList(key, channel.getNettyChannel());
    }

    public void removeFromList(String key) {
        if (contextMap.containsKey(key)) {
            contextMap.remove(key);
        }
    }
}