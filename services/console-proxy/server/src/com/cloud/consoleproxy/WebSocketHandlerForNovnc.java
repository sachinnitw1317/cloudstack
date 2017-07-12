package com.cloud.consoleproxy;

import com.cloud.consoleproxy.vnc.RfbConstants;
import org.apache.log4j.Logger;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.websocket.api.Session;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketConnect;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketClose;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketFrame;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketError;
import org.eclipse.jetty.websocket.api.annotations.WebSocket;
import org.eclipse.jetty.websocket.api.extensions.Frame;
import org.eclipse.jetty.websocket.common.WebSocketSession;
import org.eclipse.jetty.websocket.server.WebSocketHandler;
import org.eclipse.jetty.websocket.servlet.WebSocketServletFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.spec.KeySpec;
import java.util.Map;

/**
 * Created by root on 18/6/17.
 */


// remember to open port 8000 on CPVM
@WebSocket
public class WebSocketHandlerForNovnc extends WebSocketHandler {


    public static final Logger s_logger = Logger.getLogger(WebSocketHandlerForNovnc.class.getSimpleName());
    private Socket vncSocket;
    private DataInputStream is;
    private DataOutputStream os;
    private Session session;
    private boolean isConnectionStart = false;
    private int frameCount;
    /**
     * Reverse bits in byte, so least significant bit will be most significant
     * bit. E.g. 01001100 will become 00110010.
     * <p>
     * See also: http://www.vidarholen.net/contents/junk/vnc.html ,
     * http://bytecrafter
     * .blogspot.com/2010/09/des-encryption-as-used-in-vnc.html
     *
     * @param b a byte
     * @return byte in reverse order
     */
    private static byte flipByte(byte b) {
        int b1_8 = (b & 0x1) << 7;
        int b2_7 = (b & 0x2) << 5;
        int b3_6 = (b & 0x4) << 3;
        int b4_5 = (b & 0x8) << 1;
        int b5_4 = (b & 0x10) >>> 1;
        int b6_3 = (b & 0x20) >>> 3;
        int b7_2 = (b & 0x40) >>> 5;
        int b8_1 = (b & 0x80) >>> 7;
        byte c = (byte) (b1_8 | b2_7 | b3_6 | b4_5 | b5_4 | b6_3 | b7_2 | b8_1);
        return c;
    }

    @Override
    public void configure(WebSocketServletFactory webSocketServletFactory) {
        webSocketServletFactory.register(WebSocketHandlerForNovnc.class);
    }

    @Override
    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        if (this.getWebSocketFactory().isUpgradeRequest(request, response)) {
            response.addHeader("Sec-WebSocket-Protocol", "binary");
            if (this.getWebSocketFactory().acceptWebSocket(request, response)) {
                baseRequest.setHandled(true);
                return;
            }

            if (response.isCommitted()) {
                return;
            }
        }
    }

    @OnWebSocketConnect
    public void onConnect(final Session session) throws IOException, InterruptedException {

        s_logger.info("Connect: " + session.getRemoteAddress().getAddress());
        s_logger.info(session.getUpgradeRequest().getRequestURI());
        System.out.println("Responding to client");

        String queries = ((WebSocketSession) session).getRequestURI().getQuery();
        Map<String, String> queryMap = ConsoleProxyHttpHandlerHelper.getQueryMap(queries);
        String host = queryMap.get("host");
        String portStr = queryMap.get("port");
        String sid = queryMap.get("sid");
        String tag = queryMap.get("tag");
        String ticket = queryMap.get("ticket");
        String ajaxSessionIdStr = queryMap.get("sess");
        String eventStr = queryMap.get("event");
        String console_url = queryMap.get("consoleurl");
        String console_host_session = queryMap.get("sessionref");
        String vm_locale = queryMap.get("locale");
        String hypervHost = queryMap.get("hypervHost");
        String username = queryMap.get("username");
        String password = queryMap.get("password");

        if (tag == null)
            tag = "";

        long ajaxSessionId = 0;
        int event = 0;

        int port;

        if (host == null || portStr == null || sid == null)
            throw new IllegalArgumentException();

        try {
            port = Integer.parseInt(portStr);
        } catch (NumberFormatException e) {
            s_logger.warn("Invalid number parameter in query string: " + portStr);
            throw new IllegalArgumentException(e);
        }

        if (ajaxSessionIdStr != null) {
            try {
                ajaxSessionId = Long.parseLong(ajaxSessionIdStr);
            } catch (NumberFormatException e) {
                s_logger.warn("Invalid number parameter in query string: " + ajaxSessionIdStr);
                throw new IllegalArgumentException(e);
            }
        }

        if (eventStr != null) {
            try {
                event = Integer.parseInt(eventStr);
            } catch (NumberFormatException e) {
                s_logger.warn("Invalid number parameter in query string: " + eventStr);
                throw new IllegalArgumentException(e);
            }
        }

        try {
            ConsoleProxyClientParam param = new ConsoleProxyClientParam();
            param.setClientHostAddress(host);
            param.setClientHostPort(port);
            param.setClientHostPassword(sid);
            param.setClientTag(tag);
            param.setTicket(ticket);
            param.setClientTunnelUrl(console_url);
            param.setClientTunnelSession(console_host_session);
            param.setLocale(vm_locale);
            param.setHypervHost(hypervHost);
            param.setUsername(username);
            param.setPassword(password);
            proxynoVNC(session, param);
        } catch (Exception e) {

            s_logger.warn("Failed to create viewer due to " + e.getMessage(), e);

            String[] content =
                    new String[]{"<html><head></head><body>", "<div id=\"main_panel\" tabindex=\"1\">",
                            "<p>Access is denied for the console session. Please close the window and retry again</p>", "</div></body></html>"};

            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < content.length; i++)
                sb.append(content[i]);

            sendResponseString(session, sb.toString());
            return;
        }
    }


    private void proxynoVNC(Session session, ConsoleProxyClientParam param) {
        this.session = session;
        try {
            vncSocket = new Socket(param.getClientHostAddress(), param.getClientHostPort());
            frameCount = 0;
            doConnect(vncSocket, param.getClientHostPassword());
        } catch (IOException e) {
            s_logger.error("Could not connect to host", e);
        }
    }

    private void startProxyThread() {
        byte[] b = new byte[1500];
        int readBytes = -1;
        while (true) {
            try {
                vncSocket.setSoTimeout(0);

                if (is.available() > 0)
                    readBytes = is.read(b);

            } catch (IOException e) {
                e.printStackTrace();
            }

            if (readBytes == -1){
                break;
            }

            System.out.printf("read bytes %d\n", readBytes);
            if (readBytes > 0) {
                s_logger.warn("sending bytes of size" + readBytes + " from sender thread");
                sendResponseBytes(session, b, readBytes);
            }
        }
    }

    private void sendResponseString(Session session, String s) {
        try {
            session.getRemote().sendString(s);
        } catch (IOException e) {
            s_logger.error("unable to send response", e);
        }
    }

    private void sendResponseBytes(Session session, byte[] bytes, int size) {
        try {
            session.getRemote().sendBytes(ByteBuffer.wrap(bytes, 0, size));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @OnWebSocketClose
    public void onClose(int statusCode, String reason) {
        System.out.println("Close: statusCode=" + statusCode + ", reason=" + reason);
    }

    @OnWebSocketError
    public void onError(Throwable t) {
        s_logger.error("Error in WebSocket Connection : ", t);
    }

    private void doConnect(Socket socket, String password) throws IOException {
        is = new DataInputStream(socket.getInputStream());
        os = new DataOutputStream(socket.getOutputStream());

        // Initialize connection
        s_logger.warn("Stating handshake");
        handshake();
        authenticate(password);
        initialize();
        isConnectionStart = true;
        s_logger.warn("initialization done");


    }

    public void shutdown() {

        if (is != null) {
            try {
                is.close();
            } catch (Throwable e) {
                s_logger.info("[ignored]"
                        + "failed to close resource for input: " + e.getLocalizedMessage());
            }
        }

        if (os != null) {
            try {
                os.close();
            } catch (Throwable e) {
                s_logger.info("[ignored]"
                        + "failed to get close resource for output: " + e.getLocalizedMessage());
            }
        }

        if (vncSocket != null) {
            try {
                vncSocket.close();
            } catch (Throwable e) {
                s_logger.info("[ignored]"
                        + "failed to get close resource for socket: " + e.getLocalizedMessage());
            }
        }

    }

    @OnWebSocketFrame
    public void onFrame(Frame f) throws IOException {
        System.out.printf("Frame: %d\n", f.getPayloadLength());
        frameCount++;
        if (frameCount < 0)
            frameCount = 5;

        switch (frameCount){
            case 1 : {
                byte[] data = new byte[f.getPayloadLength()];
                f.getPayload().get(data);
                if (f.getPayloadLength() == 12){
                    s_logger.debug("recieved noVNC handshake");
                }
                break;
            }

            case 2 :
            case 3 :{
                byte[] data = new byte[f.getPayloadLength()];
                f.getPayload().get(data);
                break;
            }

            case 4 :{
                byte[] data = new byte[f.getPayloadLength()];
                f.getPayload().get(data);
                os.write(data);
                os.flush();
                if (isConnectionStart) {
                    isConnectionStart = false;
                    new Thread(new Runnable() {
                        @Override
                        public void run() {
                            startProxyThread();
                        }
                    }).start();
                }
            }
            default :{
                byte[] data = new byte[f.getPayloadLength()];
                f.getPayload().get(data);
                os.write(data);
                os.flush();
            }

            if (f.getType().equals(Frame.Type.CLOSE)){
                shutdown();
            }
        }
    }

    /**
     * VNC authentication.
     */
    private void authenticate(String password) throws IOException {
        // Read security type
        int readAuthTypeCount = is.read();
        int authType;
        if (readAuthTypeCount == 0){
            authType = 0;
        }else {
            authType = is.read();
        }
        os.write(authType);
        os.flush();

        switch (authType) {
            case RfbConstants.CONNECTION_FAILED: {
                // Server forbids to connect. Read reason and throw exception

                int length = is.readInt();
                byte[] buf = new byte[length];
                is.readFully(buf);
                sendResponseBytes(session, buf, length);
                String reason = new String(buf, RfbConstants.CHARSET);

                s_logger.error("Authentication to VNC server is failed. Reason: " + reason);
                throw new RuntimeException("Authentication to VNC server is failed. Reason: " + reason);
            }

            case RfbConstants.NO_AUTH: {
                // Client can connect without authorization. Nothing to do.
                break;
            }

            case RfbConstants.VNC_AUTH: {
                s_logger.info("VNC server requires password authentication");
                doVncAuth(password);
                break;
            }

            default:
                s_logger.error("Unsupported VNC protocol authorization scheme, scheme code: " + authType + ".");
                throw new RuntimeException("Unsupported VNC protocol authorization scheme, scheme code: " + authType + ".");
        }

        // 1 for send auth type count
        // 1 for sending auth type used i.e no auth required
        s_logger.warn("sending auth types and response");
        sendResponseBytes(session, new byte[]{1, 1}, 2);
        sendResponseBytes(session, new byte[]{0, 0, 0, 0}, 4);
    }

    /**
     * Encode client password and send it to server.
     */
    private void doVncAuth(String password) throws IOException {

        // Read challenge
        byte[] challenge = new byte[16];
        is.readFully(challenge);
        // Encode challenge with password
        byte[] response;
        try {
            response = encodePassword(challenge, password);
        } catch (Exception e) {
            s_logger.error("Cannot encrypt client password to send to server: " + e.getMessage());
            throw new RuntimeException("Cannot encrypt client password to send to server: " + e.getMessage());
        }

        // Send encoded challenge
        os.write(response);
        os.flush();

        // Read security result
        int authResult = is.readInt();
        switch (authResult) {
            case RfbConstants.VNC_AUTH_OK: {
                // Nothing to do
                break;
            }

            case RfbConstants.VNC_AUTH_TOO_MANY:
                s_logger.error("Connection to VNC server failed: too many wrong attempts.");
                throw new RuntimeException("Connection to VNC server failed: too many wrong attempts.");

            case RfbConstants.VNC_AUTH_FAILED:
                s_logger.error("Connection to VNC server failed: wrong password.");
                throw new RuntimeException("Connection to VNC server failed: wrong password.");

            default:
                s_logger.error("Connection to VNC server failed, reason code: " + authResult);
                throw new RuntimeException("Connection to VNC server failed, reason code: " + authResult);
        }
    }

    /**
     * Handshake with VNC server.
     */
    private void handshake() throws IOException {

        // Read protocol version
        byte[] buf = new byte[12];
        is.readFully(buf);
        String rfbProtocol = new String(buf);

        // Server should use RFB protocol 3.x
        if (!rfbProtocol.contains(RfbConstants.RFB_PROTOCOL_VERSION_MAJOR)) {
            s_logger.error("Cannot handshake with VNC server. Unsupported protocol version: \"" + rfbProtocol + "\".");
            throw new RuntimeException("Cannot handshake with VNC server. Unsupported protocol version: \"" + rfbProtocol + "\".");
        }

        // Send response: we support RFB 3.3 only
        String ourProtocolString = RfbConstants.RFB_PROTOCOL_VERSION + "\n";
        os.write(ourProtocolString.getBytes());
        s_logger.warn("sendind object of size 12");
        sendResponseBytes(session, buf, 12);
        os.flush();
    }

    /**
     * Encode password using DES encryption with given challenge.
     *
     * @param challenge a random set of bytes.
     * @param password  a password
     * @return DES hash of password and challenge
     */
    public byte[] encodePassword(byte[] challenge, String password) throws Exception {
        // VNC password consist of up to eight ASCII characters.
        byte[] key = {0, 0, 0, 0, 0, 0, 0, 0}; // Padding
        byte[] passwordAsciiBytes = password.getBytes(RfbConstants.CHARSET);
        System.arraycopy(passwordAsciiBytes, 0, key, 0, Math.min(password.length(), 8));

        // Flip bytes (reverse bits) in key
        for (int i = 0; i < key.length; i++) {
            key[i] = flipByte(key[i]);
        }

        KeySpec desKeySpec = new DESKeySpec(key);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = secretKeyFactory.generateSecret(desKeySpec);
        Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] response = cipher.doFinal(challenge);
        return response;
    }

    private void initialize() throws IOException {
        s_logger.warn("asking for exclusive access");
        os.writeByte(RfbConstants.EXCLUSIVE_ACCESS);
        os.flush();

        //   getting initializer parameter and sending them to server
        byte[] b = new byte[1500];
        int readBytes = -1;
        vncSocket.setSoTimeout(0);
        readBytes = is.read(b);
        sendResponseBytes(session, b, readBytes);

        // Read server initialization message

        // Read frame buffer size
        /*int framebufferWidth = is.readUnsignedShort();
        int framebufferHeight = is.readUnsignedShort();*/


        // Read pixel format

        /*int bitsPerPixel = is.readUnsignedByte();
        int depth = is.readUnsignedByte();

        int bigEndianFlag = is.readUnsignedByte();
        int trueColorFlag = is.readUnsignedByte();

        int redMax = is.readUnsignedShort();
        int greenMax = is.readUnsignedShort();
        int blueMax = is.readUnsignedShort();

        int redShift = is.readUnsignedByte();
        int greenShift = is.readUnsignedByte();
        int blueShift = is.readUnsignedByte();

        // Skip padding
        is.skipBytes(3);


        os.writeByte(RfbConstants.CLIENT_SET_PIXEL_FORMAT);
        // Padding
        os.writeByte(0);
        os.writeByte(0);
        os.writeByte(0);
        os.writeByte(0);
        // Send pixel format
        os.writeByte(bitsPerPixel);
        os.writeByte(depth);
        os.writeByte(bigEndianFlag);
        os.writeByte(trueColorFlag);
        os.writeShort(redMax);
        os.writeShort(greenMax);
        os.writeShort(blueMax);
        os.writeByte(redShift);
        os.writeByte(greenShift);
        os.writeByte(blueShift);
        // Padding
        os.writeByte(0);
        os.writeByte(0);
        os.writeByte(0);
        os.flush();


        // sending padding data
        os.writeByte(RfbConstants.CLIENT_SET_ENCODINGS);
        os.writeByte(0);// padding
        os.writeShort(RfbConstants.SUPPORTED_ENCODINGS_ARRAY.length);
        for (int i = 0; i < RfbConstants.SUPPORTED_ENCODINGS_ARRAY.length; i++) {
            os.writeInt(RfbConstants.SUPPORTED_ENCODINGS_ARRAY[i]);
        }
        os.flush();

        // sending frame update request and start proxying
        os.writeByte(RfbConstants.CLIENT_FRAMEBUFFER_UPDATE_REQUEST);
        os.writeByte(RfbConstants.FRAMEBUFFER_FULL_UPDATE_REQUEST);
        os.writeShort(0);
        os.writeShort(0);
        os.writeShort(framebufferWidth);
        os.writeShort(framebufferHeight);
        os.flush();*/
    }
}




