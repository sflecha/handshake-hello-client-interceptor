package sflecha.handshakehelloclientinterceptor.channelhandler;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.logging.ByteBufFormat;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.ssl.SniCompletionEvent;
import io.netty.handler.ssl.SslClientHelloHandler;
import io.netty.handler.ssl.SslContext;
import io.netty.util.AsyncMapping;
import io.netty.util.DomainNameMapping;
import io.netty.util.Mapping;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.Promise;
import io.netty.util.concurrent.ScheduledFuture;
import io.netty.util.internal.ObjectUtil;
import io.netty.util.internal.PlatformDependent;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.SSLHandshakeException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
public class TLSHandshakeReaderHandler extends SslClientHelloHandler<SslContext> {

    private static final Selection EMPTY_SELECTION = new Selection((SslContext) null, (String) null);
    private String hostname;
    private Map<Integer, byte[]> tlsExtensions;
    protected final AsyncMapping<String, SslContext> mapping;
    private ScheduledFuture<?> timeoutFuture;
    private Selection selection;

    //    private boolean handshakeRead;
    private final long handshakeTimeoutMillis = 10_000L;

    public TLSHandshakeReaderHandler(Mapping<? super String, ? extends SslContext> mapping) {
        this((AsyncMapping) (new AsyncMappingAdapter(mapping)));
    }

    public TLSHandshakeReaderHandler(AsyncMapping<String, SslContext> mapping) {
        this.mapping = mapping;
    }

    public TLSHandshakeReaderHandler(DomainNameMapping<? extends SslContext> mapping) {
        this((Mapping) mapping);
    }

    @Override
    protected Future<SslContext> lookup(ChannelHandlerContext ctx, ByteBuf clientHello) throws Exception {
        this.tlsExtensions = clientHello == null ? null : extractTlsExtensions(clientHello);
        this.hostname = tlsExtensions == null || tlsExtensions.get(0) == null ? null : new String(tlsExtensions.get(0), "UTF-8");
//        this.hostname = clientHello == null ? null : extractSniHostname(clientHello);
        return this.mapping.map(hostname, ctx.executor().newPromise());
    }

    @Override
    protected void onLookupComplete(ChannelHandlerContext ctx, Future<SslContext> future) throws Exception {
        if (this.timeoutFuture != null) {
            this.timeoutFuture.cancel(false);
        }

        try {
            if (!future.isSuccess()) {
                Throwable cause = future.cause();
                if (cause instanceof Error) {
                    throw (Error) cause;
                } else {
                    throw new DecoderException("failed to get the SslContext for " + hostname, cause);
                }
            } else {
                SslContext sslContext = (SslContext) future.getNow();
                this.selection = new Selection(sslContext, hostname);

                try {
//                    this.handshakeRead = true;
                    this.replaceHandler(ctx, tlsExtensions, sslContext);
                } catch (Throwable var6) {
                    this.selection = EMPTY_SELECTION;
                    PlatformDependent.throwException(var6);
                }

            }
        } finally {
            Throwable cause = future.cause();
            if (cause == null) {
                ctx.fireUserEventTriggered(new SniCompletionEvent(hostname));
            } else {
                ctx.fireUserEventTriggered(new SniCompletionEvent(hostname, cause));
            }
        }
    }

    protected void replaceHandler(ChannelHandlerContext ctx, Map<Integer, byte[]> tlsExtensions, SslContext sslContext) throws Exception {

        ctx.pipeline().remove(this);
        if (tlsExtensions != null) {
            ctx.pipeline().addAfter("reactor.left.httpCodec", SSLtoHttpAggregatorHandler.class.getSimpleName(), new SSLtoHttpAggregatorHandler(tlsExtensions));
            ctx.pipeline().addBefore("reactor.left.httpCodec", "HTTPSDecodeLoggingHandler", new LoggingHandler("HTTPSDecodeLoggingHandler", LogLevel.INFO, ByteBufFormat.HEX_DUMP));
        }

//        SslHandler sslHandler = null;
//        try {
//            sslHandler = sslContext.newHandler(ctx.alloc());
//            sslHandler.setHandshakeTimeoutMillis(this.handshakeTimeoutMillis);
//            ctx.pipeline().replace(this, SslHandler.class.getName(), sslHandler);
//            sslHandler = null;
//        } finally {
//            if (sslHandler != null) {
//                ReferenceCountUtil.safeRelease(sslHandler.engine());
//            }
//        }
    }

    private void checkStartTimeout(final ChannelHandlerContext ctx) {
        if (this.handshakeTimeoutMillis > 0L && this.timeoutFuture == null) {
            this.timeoutFuture = ctx.executor().schedule(() -> {
                if (ctx.channel().isActive()) {
                    SSLHandshakeException exception = new SSLHandshakeException("handshake timed out after " + TLSHandshakeReaderHandler.this.handshakeTimeoutMillis + "ms");
                    ctx.fireUserEventTriggered(new SniCompletionEvent(exception));
                    ctx.close();
                }

            }, this.handshakeTimeoutMillis, TimeUnit.MILLISECONDS);
        }
    }

    private static Map<Integer, byte[]> extractTlsExtensions(ByteBuf in) {

        Map<Integer, byte[]> tlsExtensions = new HashMap<>();

        int offset = in.readerIndex();
        int endOffset = in.writerIndex();
        offset += 34;
        if (endOffset - offset >= 6) {
            int sessionIdLength = in.getUnsignedByte(offset);
            offset += sessionIdLength + 1;
            int cipherSuitesLength = in.getUnsignedShort(offset);
            offset += cipherSuitesLength + 2;
            int compressionMethodLength = in.getUnsignedByte(offset);
            offset += compressionMethodLength + 1;
            int extensionsLength = in.getUnsignedShort(offset);
            offset += 2;
            int extensionsLimit = offset + extensionsLength;
            if (extensionsLimit <= endOffset) {
                while (extensionsLimit - offset >= 4) {
                    int extensionType = in.getUnsignedShort(offset);
                    offset += 2;
                    int extensionLength = in.getUnsignedShort(offset);
                    offset += 2;
                    if (extensionsLimit - offset < extensionLength) {
                        break;
                    }

                    log.info("TLS Handshake ClientHello message extension ---> type: {}, extension length: {}, extensionsLimit: {}", extensionType, extensionLength, extensionsLimit);

//                    if (extensionType == 0) {
//                        offset += 2;
//                        if (extensionsLimit - offset >= 3) {
//                            int serverNameType = in.getUnsignedByte(offset);
//                            ++offset;
//                            if (serverNameType == 0) {
//                                int serverNameLength = in.getUnsignedShort(offset);
//                                offset += 2;
//                                if (extensionsLimit - offset >= serverNameLength) {
//                                    String hostname = in.toString(offset, serverNameLength, CharsetUtil.US_ASCII);
//                                    return hostname.toLowerCase(Locale.US);
//                                }
//                            }
//                        }
//                        break;
//                    }
                    if (extensionLength > 0) {
//                        byte[] extensionByteArray = new byte[extensionLength];
//                        for (int extOffset = offset, i = 0; i < extensionLength; extOffset++, i++) {
//                            byte extensionByte = (byte)(in.getUnsignedByte(extOffset) & 0xff);
//                            extensionByteArray[i] = extensionByte;
//                        }
//                        log.info(Arrays.toString(extensionByteArray));
                        StringBuilder sb = new StringBuilder();
                        ByteBufUtil.appendPrettyHexDump(sb, in, offset, extensionLength);
                        log.info(sb.toString());

                        tlsExtensions.put(extensionType, ByteBufUtil.getBytes(in, offset, extensionLength));
                    } else {
                        tlsExtensions.put(extensionType, new byte[0]);
                    }

                    offset += extensionLength;
                }
            }
        }

        return tlsExtensions;
    }

    private static final class Selection {
        private SslContext context;
        final String hostname;

        Selection(SslContext context, String hostname) {
            this.context = context;
            this.hostname = hostname;
        }
    }

    private record AsyncMappingAdapter(
            Mapping<? super String, ? extends SslContext> mapping) implements AsyncMapping<String, SslContext> {
        private AsyncMappingAdapter(Mapping<? super String, ? extends SslContext> mapping) {
            this.mapping = (Mapping) ObjectUtil.checkNotNull(mapping, "mapping");
        }

        public Future<SslContext> map(String input, Promise<SslContext> promise) {
            SslContext context;
            try {
                context = (SslContext) this.mapping.map(input);
            } catch (Throwable var5) {
                return promise.setFailure(var5);
            }

            return promise.setSuccess(context);
        }
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        ctx.fireChannelActive();
        this.checkStartTimeout(ctx);
    }
}
