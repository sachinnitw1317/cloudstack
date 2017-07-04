package com.cloud.consoleproxy;

import com.cloud.consoleproxy.util.Logger;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Created by root on 9/6/17.
 */
public class NoVncConsoleHandler implements HttpHandler {
    private static final Logger s_logger = Logger.getLogger(NoVncConsoleHandler.class);

    public NoVncConsoleHandler() {

    }

    @Override
    public void handle(HttpExchange t) throws IOException {
        try {
            if (s_logger.isTraceEnabled())
                s_logger.trace("noVNC Console handler" + t.getRequestURI());

            long startTick = System.currentTimeMillis();

            doHandle(t);

            if (s_logger.isTraceEnabled())
                s_logger.trace(t.getRequestURI() + " process time " + (System.currentTimeMillis() - startTick) + " ms");
        } catch (IOException e) {
            throw e;
        } catch (IllegalArgumentException e) {
            s_logger.warn("Exception, ", e);
            t.sendResponseHeaders(400, -1);     // bad request
        } catch (Throwable e) {
            s_logger.error("Unexpected exception, ", e);
            t.sendResponseHeaders(500, -1);     // server error
        } finally {
            t.close();
        }
    }

    private void doHandle(HttpExchange httpExchange) throws IOException {
        String queries = httpExchange.getRequestURI().getQuery();
        if (s_logger.isTraceEnabled())
            s_logger.trace("Handle WebSocket Console request " + queries);


        /* no authentication done here
        *  authentication for the request would be added on websocket connection
        *  initialization
        */
        String[] content =
                new String[]{"<html>",
                        "<head>",
                        "<script type=\"text/javascript\" language=\"javascript\" src=\"/resource/js/jquery.js\"></script>",
                        "<script> \n" +
                                "    $(function(){\n" +
                                "      $(\"#vncpage\").load(\"/resource/noVNC/novnc.html\"); \n" +
                                "    });\n" +
                                "    </script>",
                        " <body> \n" +
                                "     <div id=\"vncpage\"></div>\n" +
                                "  </body> ",
                        "</head>",
                        "</html>"};

        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < content.length; i++)
            sb.append(content[i]);

        sendResponse(httpExchange, "text/html", sb.toString());
    }


    private void sendResponse(HttpExchange httpExchange, String contentType, String response) throws IOException {
        Headers hds = httpExchange.getResponseHeaders();
        hds.set("Content-Type", contentType);

        httpExchange.sendResponseHeaders(200, response.length());

        OutputStream os = httpExchange.getResponseBody();
        try {
            os.write(response.getBytes());
        } finally {
            os.close();
        }
    }
}
