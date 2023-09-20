package sflecha.handshakehelloclientinterceptor.channelhandler;

import io.netty.channel.Channel;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.ssl.SslContext;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLEngine;

@Slf4j
public class TestChannel extends ChannelDuplexHandler {

    private final SSLEngine sslEngine;
    private final SslContext clientSslContext;
    private final SslContext serverSideSslContext;
    private final Channel channel;

    public TestChannel(SSLEngine sslEngine, SslContext clientSslContext, SslContext serverSideSslContext, Channel channel) {
        this.sslEngine = sslEngine;
        this.clientSslContext = clientSslContext;
        this.serverSideSslContext = serverSideSslContext;
        this.channel = channel;
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) throws Exception {
        super.channelReadComplete(ctx);
        log.info("[NETTY CHANNEL PIPELINE] -----> {}", channel.pipeline().names().toString());
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {

        super.channelRead(ctx, msg);
    }


}