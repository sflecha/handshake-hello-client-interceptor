package sflecha.handshakehelloclientinterceptor.channelhandler;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageDecoder;
import io.netty.handler.codec.http.DefaultHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpRequest;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public class SSLtoHttpAggregatorHandler extends MessageToMessageDecoder<HttpRequest> {

    private final Map<Integer, byte[]> sslExtensions;

    public SSLtoHttpAggregatorHandler(Map<Integer, byte[]> sslExtensions) {
        this.sslExtensions = sslExtensions;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {

        log.info("----> tsl to http aggregator handler read");
        log.info("----> tls extensions:");
        sslExtensions.forEach((extensionType, content) -> {
            log.info("--------> {}: {}", extensionType, bytesToHex(content));
        });
        super.channelRead(ctx, msg);
    }

    @Override
    protected void decode(ChannelHandlerContext channelHandlerContext, HttpRequest r, List<Object> out) throws Exception {

        HttpHeaders headers = r.headers();
        if (headers.contains(HttpHeaderNames.CONTENT_LENGTH)) {
            headers.remove(HttpHeaderNames.CONTENT_LENGTH);
        }
        for (Map.Entry<String, String> entry : getRequestHeaders().entrySet()) {
            try {
                headers.add(entry.getKey(), entry.getValue());
            } catch (IllegalArgumentException e) {
                log.warn("invalid encode for {}:{}", entry.getKey(), entry.getValue());
            }
        }

        HttpRequest copy = new DefaultHttpRequest(r.protocolVersion(), r.method(), r.uri());
        copy.headers().set(r.headers());
        copy.setDecoderResult(r.decoderResult());
        out.add(copy);

    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    //    @Override
    public Map<String, String> getRequestHeaders() {
        Map<String, String> headers = new HashMap<>();
        for (Map.Entry<Integer, byte[]> entry : sslExtensions.entrySet()) {
            headers.put("X-TLS-" + entry.getKey(), bytesToHex(entry.getValue()));
        }

        return headers;
    }

}
