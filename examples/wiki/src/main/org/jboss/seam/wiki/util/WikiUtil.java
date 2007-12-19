/*
 * JBoss, Home of Professional Open Source
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.jboss.seam.wiki.util;

import org.jboss.seam.Component;
import org.jboss.seam.core.Conversation;
import org.jboss.seam.wiki.core.action.prefs.WikiPreferences;
import org.jboss.seam.wiki.core.model.*;
import org.jboss.seam.wiki.core.engine.WikiTextParser;
import org.jboss.seam.wiki.core.engine.WikiLinkResolver;
import org.jboss.seam.wiki.core.engine.NullWikiTextRenderer;
import org.jboss.seam.wiki.core.engine.MacroWikiTextRenderer;

import javax.faces.context.FacesContext;
import javax.imageio.ImageIO;
import javax.servlet.http.HttpSession;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigDecimal;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Date;
import java.util.regex.Pattern;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;

import antlr.RecognitionException;
import antlr.ANTLRException;

/**
 * Adds stuff to and for JSF that should be there but isn't. Also stuff that is exposed
 * as a Facelets function, and various other useful static methods that are called from
 * everywhere.
 *
 * @author Christian Bauer
 */
public class WikiUtil {

    // Disable caching of imags (e.g. captcha) by appending this as a random URL parameter
    public static int generateRandomNumber() {
        return (int) Math.round(1 + (Math.random()*1000000));
    }

    // Creates clean alphanumeric UpperCaseCamelCase
    public static String convertToWikiName(String realName) {
        StringBuilder wikiName = new StringBuilder();
        // Remove everything that is not alphanumeric or whitespace, then split on word boundaries
        String[] tokens = realName.replaceAll("[^\\p{Alnum}|\\s]+", "").split("\\s");
        for (String token : tokens) {
            // Append word, uppercase first letter of word
            if (token.length() > 1) {
                wikiName.append(token.substring(0,1).toUpperCase());
                wikiName.append(token.substring(1));
            } else {
                wikiName.append(token.toUpperCase());
            }
        }
        return wikiName.toString();
    }

    public static String truncateString(String string, int length, String appendString) {
        if (string.length() <= length) return string;
        return string.substring(0, length-1) + appendString;
    }

    public static String concat(String a, String b) {
        return a + b;
    }

    // Display all roles for a particular access level
    public static Role.AccessLevel resolveAccessLevel(Integer accessLevel) {
        List<Role.AccessLevel> accessLevels = (List<Role.AccessLevel>)Component.getInstance("accessLevelsList");
        return accessLevels.get(
                accessLevels.indexOf(new Role.AccessLevel(accessLevel, null))
               );
    }

    // Rendering made easy
    public static String renderPlainURL(WikiNode node) {
// TODO: Fixme        if (node.isInstance(File.class) return renderFileLink((File)node);
        WikiPreferences prefs = (WikiPreferences) Component.getInstance("wikiPreferences");
        String url = "";
        if (node.isInstance(WikiDocument.class)) {
            url = prefs.getBaseUrl() + "/docDisplayPlain.seam?documentId=" + node.getId();
        } else if (node.isInstance(WikiDirectory.class)) {
            WikiDirectory dir = (WikiDirectory)node;
            if (dir.getDefaultFile() != null) {
                url = prefs.getBaseUrl() + "/docDisplayPlain.seam?documentId=" + dir.getDefaultFile().getId();
            } else {
                url = prefs.getBaseUrl() + "/dirDisplayPlain.seam?directoryId=" + node.getId();
            }
        }
        if (url.length() > 0) url = url + "&amp;cid=" + Conversation.instance().getId();
        return url;
    }

    public static String renderURL(WikiNode node) {
        if (node == null || node.getId() == null) return "";
        WikiPreferences wikiPrefs = (WikiPreferences) Component.getInstance("wikiPreferences");
        return wikiPrefs.isRenderPermlinks() ? renderPermURL(node) : renderWikiURL(node);
    }

    public static String renderPermURL(WikiNode node) {
        if (node == null || node.getId() == null) return "";
        WikiPreferences prefs = (WikiPreferences)Component.getInstance("wikiPreferences");
        return prefs.getBaseUrl() + node.getPermURL(prefs.getPermlinkSuffix());
    }

    public static String renderWikiURL(WikiNode node) {
        if (node == null || node.getId() == null) return "";
        WikiPreferences prefs = (WikiPreferences)Component.getInstance("wikiPreferences");
        return prefs.getBaseUrl() + node.getWikiURL();
    }

    public static String displayFilesize(int fileSizeInBytes) {
        // TODO: Yeah, that could be done smarter..
        if (fileSizeInBytes >= 1073741824) {
            return new BigDecimal(fileSizeInBytes / 1024 / 1024 / 1024) + " GiB";
        }else if (fileSizeInBytes >= 1048576) {
            return new BigDecimal(fileSizeInBytes / 1024 / 1024) + " MiB";
        } else if (fileSizeInBytes >= 1024) {
            return new BigDecimal(fileSizeInBytes / 1024) + " KiB";
        } else {
            return new BigDecimal(fileSizeInBytes) + " Bytes";
        }
    }

    public static String encodeURL(String string) {
        try {
            return URLEncoder.encode(string, "UTF-8");
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public static String escapeEmailURL(String string) {
        WikiPreferences wikiPrefs = (WikiPreferences) Component.getInstance("wikiPreferences");
        return string.length() >= 7 && string.substring(0, 7).equals("mailto:")
                ? string.replaceAll("@", wikiPrefs.getAtSymbolReplacement())
                : string;
    }

    public static String escapeAtSymbol(String string) {
        WikiPreferences wikiPrefs = (WikiPreferences) Component.getInstance("wikiPreferences");
        return string.replaceAll("@", wikiPrefs.getAtSymbolReplacement());
    }

    public static String escapeHtml(String string, boolean convertNewlines) {
        if (string == null) return null;
        StringBuilder sb = new StringBuilder();
        String htmlEntity;
        char c;
        for (int i = 0; i < string.length(); ++i) {
            htmlEntity = null;
            c = string.charAt(i);
            switch (c) {
                case '<': htmlEntity = "&lt;"; break;
                case '>': htmlEntity = "&gt;"; break;
                case '&': htmlEntity = "&amp;"; break;
                case '"': htmlEntity = "&quot;"; break;
            }
            if (htmlEntity != null) {
                sb.append(htmlEntity);
            } else {
                sb.append(c);
            }
        }
        if (convertNewlines) {
            return sb.toString().replaceAll("\n", "<br/>");
        }
        return sb.toString();
    }

    public static String removeMacros(String string) {
        String REGEX_MACRO = Pattern.quote("[") + "<=[a-z]{1}?[a-zA-Z0-9]+?" + Pattern.quote("]");
        return string.replaceAll(REGEX_MACRO, "");

    }

    // TODO: This would be the job of a more flexible seam text parser...
    public static String disableFloats(String string) {
        return string.replaceAll("float:\\s?(right)|(left)", "float:none")
                     .replaceAll("width:\\s?[0-9]+\\s?(px)", "width:100%")
                     .replaceAll("width:\\s?[0-9]+\\s?(%)", "width:100%");
    }

    public static byte[] resizeImage(byte[] imageData, String contentType, int width) {
        ImageIcon icon = new ImageIcon(imageData);

        double ratio = (double) width / icon.getIconWidth();
        int resizedHeight = (int) (icon.getIconHeight() * ratio);

        int imageType = "image/png".equals(contentType)
                        ? BufferedImage.TYPE_INT_ARGB
                        : BufferedImage.TYPE_INT_RGB;
        BufferedImage bImg = new BufferedImage(width, resizedHeight, imageType);
        Graphics2D g2d = bImg.createGraphics();
        g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC);
        g2d.drawImage(icon.getImage(), 0, 0, width, resizedHeight, null);
        g2d.dispose();

        String formatName = "";
        if ("image/png".equals(contentType))       formatName = "png";
        else if ("image/jpeg".equals(contentType)) formatName = "jpeg";

        ByteArrayOutputStream baos = new ByteArrayOutputStream(1024);
        try {
            ImageIO.write(bImg, formatName, baos);
            return baos.toByteArray();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static Throwable unwrap(Throwable throwable) throws IllegalArgumentException {
        if (throwable == null) {
            throw new IllegalArgumentException("Cannot unwrap null throwable");
        }
        for (Throwable current = throwable; current != null; current = current.getCause()) {
            throwable = current;
        }
        return throwable;
    }

    public static int getSessionTimeoutSeconds() {
        return ((HttpSession) FacesContext.getCurrentInstance().getExternalContext().getSession(true)).getMaxInactiveInterval();
    }

    /**
     * Moves the element at <tt>oldPosition</tt> to <tt>newPosition</tt>.
     * <p>
     * Correctly handles forward and backward shifting of previous or subsequent elements.
     *
     * @param list the list that is affected
     * @param oldPosition the position of the element to move
     * @param newPosition the new position of the element
     */
    public static void shiftListElement(List list, int oldPosition, int newPosition) {
        if (oldPosition> newPosition) {
            Collections.rotate(list.subList(newPosition, oldPosition+1), +1);
        } else if (oldPosition < newPosition) {
            Collections.rotate(list.subList(oldPosition, newPosition+1), -1);
        }
    }

    /**
     * Can't use col.size() in a value binding. Why can't I call arbitrary methods, even
     * with arguments, in a value binding? Java needs properties badly.
     */
    public static int sizeOf(Collection col) {
        return col == null ? 0 : col.size();
    }

    /**
     * EL doesn't support a String lenth() operator.
     */
    public static int length(String string) {
        return string == null ? 0 : string.length();
    }

    public static String repeatString(String s, Integer count) {
        StringBuilder spaces = new StringBuilder();
        for (int i = 0; i < count; i++) {
            spaces.append(s);
        }
        return spaces.toString();
    }

    public static String formatDate(Date date) {
        SimpleDateFormat fmt = new SimpleDateFormat("MMM dd, yyyy hh:mm aaa");
        return fmt.format(date);
    }

    public static String attachSignature(String wikiText, String sig) {
        StringBuilder builder = new StringBuilder();
        builder.append(wikiText).append("\n\n-- ").append(sig);
        return builder.toString();
    }

    public static boolean isRegularUser(User user) {
        User guestUser = (User)Component.getInstance("guestUser");
        User adminUser = (User)Component.getInstance("adminUser");
        if (user.getId().equals(guestUser.getId()) || user.getId().equals(adminUser.getId())) return false;
        return true;
    }

    /**
     * Used for conditional rendering of JSF messages, again, inflexible EL can't take value bindings with arguments
     * or support simple String concat...
     */
    public static boolean hasMessage(String namingContainer, String componentId) {
        return FacesContext.getCurrentInstance().getMessages(namingContainer.replaceAll("\\\\", "") + ":" + componentId).hasNext();
    }

}
