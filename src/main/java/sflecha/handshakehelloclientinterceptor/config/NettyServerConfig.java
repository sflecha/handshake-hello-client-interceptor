package sflecha.handshakehelloclientinterceptor.config;

import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.logging.ByteBufFormat;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.DomainNameMappingBuilder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.embedded.netty.NettyReactiveWebServerFactory;
import org.springframework.boot.web.embedded.netty.NettyServerCustomizer;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.netty.http.server.HttpServer;
import sflecha.handshakehelloclientinterceptor.channelhandler.TLSHandshakeReaderHandler;
import sflecha.handshakehelloclientinterceptor.channelhandler.TestChannel;

import javax.net.ssl.SSLException;

@Configuration
@Slf4j
public class NettyServerConfig {

    @Bean
    public WebServerFactoryCustomizer<NettyReactiveWebServerFactory> nettyReactiveWebServerFactoryWebServerFactoryCustomizer() {
        return new WebServerFactoryCustomizer<NettyReactiveWebServerFactory>() {
            @Override
            public void customize(NettyReactiveWebServerFactory factory) {
            }
        };
    }

    @Bean
    public NettyReactiveWebServerFactory nettyReactiveWebServerFactory() {
        NettyReactiveWebServerFactory webServerFactory = new NettyReactiveWebServerFactory();
        webServerFactory.addServerCustomizers(new EventLoopNettyCustomizer());
        webServerFactory.addServerCustomizers(new MyNettyServerCustomizer());
        return webServerFactory;
    }

    private static class EventLoopNettyCustomizer implements NettyServerCustomizer {

        @Override
        public HttpServer apply(HttpServer httpServer) {
            EventLoopGroup eventLoopGroup = new NioEventLoopGroup();
            eventLoopGroup.register(new NioServerSocketChannel());
            return httpServer.runOn(eventLoopGroup);
        }
    }

    private static class MyNettyServerCustomizer implements NettyServerCustomizer {

        @Override
        public HttpServer apply(HttpServer httpServer) {

            return httpServer.doOnChannelInit((connectionObserver, channel, socketAddress) -> {

                SslContext clientSslContext;
                SslContext serverSideSslContext = httpServer.configuration().sslProvider().getSslContext();
                try {
                    clientSslContext = SslContextBuilder.forClient().build();
                } catch (SSLException e) {
                    throw new RuntimeException(e);
                }
                SslHandler sslHandler = channel.pipeline().get(SslHandler.class);

                channel.pipeline()
//                        .addAfter("reactor.left.sslHandler", "loggingHandler2", new LoggingHandler(LogLevel.INFO, ByteBufFormat.HEX_DUMP)
//                            ,new SSLExtensionHandler(new DomainNameMappingBuilder<>(httpServer.configuration().sslProvider().getSslContext()).build())
//                        .addBefore("reactor.left.sslHandler", "sniHandler",new SniHandler(new DomainNameMappingBuilder<>(serverSideSslContext).build()))
//                        .addBefore("reactor.left.sslHandler", "sniHandler",new SniHandler(new DomainNameMappingBuilder<>(clientSslContext).build()))
                        .addBefore("reactor.left.sslHandler", "tlsExtensionHandler", new TLSHandshakeReaderHandler(new DomainNameMappingBuilder<>(serverSideSslContext).build()))
                        .addFirst(
                                new LoggingHandler(LogLevel.INFO, ByteBufFormat.HEX_DUMP)
//                                , new SniHandler(new DomainNameMappingBuilder<>(serverSideSslContext).build())
                                , new TestChannel(sslHandler.engine(), clientSslContext, serverSideSslContext, channel)
                        )
                ;
//                    channel.pipeline().addAfter("reactor.left.sslReader","reactor.left.sniHandler", new SniHandler(new DomainNameMappingBuilder<>(httpServer.configuration().sslProvider().getSslContext()).build()));

            });
        }
    }

}
