//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.scripts;

import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.util.Iterator;
import java.util.Vector;
import java.util.regex.Pattern;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.htmlparser.Attribute;
import org.htmlparser.Node;
import org.htmlparser.Parser;
import org.htmlparser.PrototypicalNodeFactory;
import org.htmlparser.tags.DoctypeTag;
import org.htmlparser.util.NodeIterator;
import org.htmlparser.util.ParserException;
import org.springframework.extensions.surf.util.I18NUtil;
import org.springframework.extensions.webscripts.connector.HttpMethod;
import org.springframework.extensions.webscripts.connector.RemoteClient;
import org.springframework.extensions.webscripts.ui.common.StringUtils;

public class SlingshotRemoteClient extends RemoteClient {
    private static final Pattern CONTENT_PATTERN_TO_CHECK = Pattern.compile(".*/(api|slingshot)/(node|path)/(content.*/)?workspace/SpacesStore/.+");
    private static final Pattern TRASHCAN_PATTERN_TO_CHECK = Pattern.compile(".*/(api|slingshot)/(node|path)/(content.*/)?archive/SpacesStore/.+");
    private static final Pattern CONTENT_PATTERN_TO_WHITE_LIST = Pattern.compile(".*/api/node/workspace/SpacesStore/[a-z0-9-]+/content/thumbnails/webpreview");
    private static final Pattern SLINGSHOT_WIKI_PAGE_PATTERN = Pattern.compile(".*/slingshot/wiki/page/.*");
    private static final Pattern SLINGSHOT_WIKI_VERSION_PATTERN = Pattern.compile(".*/slingshot/wiki/version/.*");
    private boolean swfEnabled = false;

    public SlingshotRemoteClient() {
    }

    public void setSwfEnabled(boolean swfEnabled) {
        this.swfEnabled = swfEnabled;
    }

    protected void copyResponseStreamOutput(URL url, HttpServletResponse res, OutputStream out, HttpResponse response, String contentType, int bufferSize) throws IOException {
        boolean processed = false;
        if (res != null && this.getRequestMethod() == HttpMethod.GET && response.getStatusLine().getStatusCode() >= 200 && response.getStatusLine().getStatusCode() < 300) {
            Header cd = response.getFirstHeader("Content-Disposition");
            if ((cd == null || !cd.getValue().startsWith("attachment")) && (contentType != null && (CONTENT_PATTERN_TO_CHECK.matcher(url.getPath()).matches() && !CONTENT_PATTERN_TO_WHITE_LIST.matcher(url.getPath()).matches() || SLINGSHOT_WIKI_PAGE_PATTERN.matcher(url.getPath()).matches() || SLINGSHOT_WIKI_VERSION_PATTERN.matcher(url.getPath()).matches()) || TRASHCAN_PATTERN_TO_CHECK.matcher(url.getPath()).matches())) {
                String mimetype = contentType;
                String encoding = null;
                int csi = contentType.indexOf("charset=");
                if (csi != -1) {
                    mimetype = contentType.substring(0, csi - 1).toLowerCase();
                    encoding = contentType.substring(csi + "charset=".length());
                }

                if (!mimetype.contains("text/html") && !mimetype.contains("application/xhtml+xml") && (!mimetype.contains("text/xml") || encoding.contains("UTF-16"))) {
                    if ((mimetype.contains("application/x-shockwave-flash") || mimetype.contains("image/svg+xml")) && !this.swfEnabled) {
                        String msg = I18NUtil.getMessage("security.insecuremimetype");

                        try {
                            byte[] bytes = encoding != null ? msg.getBytes(encoding) : msg.getBytes();
                            res.setContentType("text/plain");
                            res.setContentLength(bytes.length);
                            out.write(bytes);
                        } finally {
                            out.close();
                        }

                        processed = true;
                    }
                } else {
                    ByteArrayOutputStream bos = new ByteArrayOutputStream(bufferSize);
                    InputStream input;
                    if (response.getEntity() != null && (input = response.getEntity().getContent()) != null) {
                        try {
                            byte[] buffer = new byte[bufferSize];

                            for(int read = input.read(buffer); read != -1; read = input.read(buffer)) {
                                for(int i = 0; i < read; ++i) {
                                    if (buffer[i] == 0) {
                                        res.setContentLength(0);
                                        out.close();
                                        return;
                                    }
                                }

                                bos.write(buffer, 0, read);
                            }
                        } finally {
                            input.close();
                        }

                        String content = encoding != null ? new String(bos.toByteArray(), encoding) : new String(bos.toByteArray());
                        if (!mimetype.contains("text/html") && !mimetype.contains("application/xhtml+xml")) {
                            if (mimetype.contains("text/xml")) {
                                res.setContentType("text/plain");
                            } else if (mimetype.contains("text/x-component")) {
                                res.setContentType("text/plain");
                            }
                        } else {
                            content = StringUtils.stripUnsafeHTMLDocument(content, false);
                        }

                        try {
                            byte[] bytes = encoding != null ? content.getBytes(encoding) : content.getBytes();
                            res.setContentLength(bytes.length);
                            out.write(bytes);
                        } finally {
                            out.close();
                        }
                    }

                    processed = true;
                }
            }
        }

        if (!processed) {
            super.copyResponseStreamOutput(url, res, out, response, contentType, bufferSize);
        }

    }

    protected boolean hasDocType(String content, String docType, boolean encode) {
        try {
            Parser parser = Parser.createParser(content, "UTF-8");
            PrototypicalNodeFactory factory = new PrototypicalNodeFactory();
            parser.setNodeFactory(factory);
            NodeIterator itr = parser.elements();

            while(true) {
                Vector attrs;
                do {
                    do {
                        Node node;
                        do {
                            if (!itr.hasMoreNodes()) {
                                return false;
                            }

                            node = itr.nextNode();
                        } while(!(node instanceof DoctypeTag));

                        DoctypeTag docTypeTag = (DoctypeTag)node;
                        attrs = docTypeTag.getAttributesEx();
                    } while(attrs == null);
                } while(attrs.size() <= 1);

                Iterator var10 = attrs.iterator();

                while(var10.hasNext()) {
                    Attribute attr = (Attribute)var10.next();
                    String name = attr.getName();
                    if (name != null && name.equalsIgnoreCase(docType)) {
                        return true;
                    }
                }
            }
        } catch (ParserException var13) {
            return false;
        }
    }
}
