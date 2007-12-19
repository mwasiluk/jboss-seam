package org.jboss.seam.wiki.core.engine;

import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.log.Log;
import org.jboss.seam.wiki.core.dao.WikiNodeDAO;
import org.jboss.seam.wiki.core.model.*;
import org.jboss.seam.wiki.util.WikiUtil;

import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A default implementation of <tt>WikiLinkResolver</tt>.
 *
 * @author Christian Bauer
 */
@Name("wikiLinkResolver")
@AutoCreate
public class DefaultWikiLinkResolver implements WikiLinkResolver {

    @Logger static Log log;

    // Render these strings whenever [=>wiki://123] needs to be resolved but can't
    public static final String BROKENLINK_URL = "FileNotFound";
    public static final String BROKENLINK_DESCRIPTION = "?BROKEN LINK?";

    @In
    private WikiNodeDAO wikiNodeDAO;

    @In
    Map<String, LinkProtocol> linkProtocolMap;

    public String convertToWikiProtocol(Set<WikiFile> linkTargets, Long currentAreaNumber, String wikiText) {
        if (wikiText == null) return null;

        StringBuffer replacedWikiText = new StringBuffer(wikiText.length());
        Matcher matcher = Pattern.compile(REGEX_WIKILINK_FORWARD).matcher(wikiText);

        // Replace with [Link Text=>wiki://<node id>] or leave as is if not found
        while (matcher.find()) {
            String linkText = matcher.group(2);
            WikiFile file = resolveCrossAreaLinkText(currentAreaNumber, linkText);
            if (file != null) {
                matcher.appendReplacement(replacedWikiText, "[$1=>wiki://" + file.getId() + "]");
                linkTargets.add(file);
            }
        }
        matcher.appendTail(replacedWikiText);
        return replacedWikiText.toString();
    }

    public String convertFromWikiProtocol(Long currentAreaNumber, String wikiText) {
        if (wikiText == null) return null;
        
        StringBuffer replacedWikiText = new StringBuffer(wikiText.length());
        Matcher matcher = Pattern.compile(REGEX_WIKILINK_REVERSE).matcher(wikiText);

        // Replace with [Link Text=>Page Name] or replace with BROKENLINK "page name"
        while (matcher.find()) {

            // Find the node by PK
            WikiFile file = wikiNodeDAO.findWikiFile(Long.valueOf(matcher.group(2)));

            // Node is in current area, just use its name
            if (file != null && file.getAreaNumber().equals(currentAreaNumber)) {
                matcher.appendReplacement(replacedWikiText, "[$1=>" + file.getName() + "]");

            // Node is in different area, prepend the area name
            } else if (file != null && !file.getAreaNumber().equals(currentAreaNumber)) {
                WikiDirectory area = wikiNodeDAO.findArea(file.getAreaNumber());
                matcher.appendReplacement(replacedWikiText, "[$1=>" + area.getName() + "|" + file.getName() + "]");

            // Couldn't find it anymore, its a broken link
            } else {
                matcher.appendReplacement(replacedWikiText, "[$1=>" + BROKENLINK_DESCRIPTION + "]");
            }
        }
        matcher.appendTail(replacedWikiText);
        return replacedWikiText.toString();
    }

    public void resolveLinkText(Long currentAreaNumber, Map<String, WikiLink> links, String linkText) {

        // Don't resolve twice
        if (links.containsKey(linkText)) return;

        Matcher wikiProtocolMatcher = Pattern.compile(REGEX_WIKI_PROTOCOL).matcher(linkText);
        Matcher knownProtocolMatcher = Pattern.compile(REGEX_KNOWN_PROTOCOL).matcher(linkText);
        Matcher customProtocolMatcher = Pattern.compile(REGEX_CUSTOM_PROTOCOL).matcher(linkText);

        WikiLink wikiLink;

        // Check if its a common protocol
        if (knownProtocolMatcher.find()) {
            wikiLink = new WikiLink(false, true);
            wikiLink.setUrl(linkText);
            wikiLink.setDescription(linkText);
            log.debug("link resolved to known protocol: " + linkText);

        // Check if it is a wiki protocol
        } else if (wikiProtocolMatcher.find()) {

            // Find the node by PK
            WikiFile file = wikiNodeDAO.findWikiFile(Long.valueOf(wikiProtocolMatcher.group(1)));
            if (file != null) {
                wikiLink = new WikiLink(false, false);
                wikiLink.setFile(file);
                wikiLink.setDescription(file.getName());
                log.debug("wiki link resolved to existing node: " + linkText);
            } else {
                // Can't do anything, [=>wiki://123] no longer exists
                wikiLink = new WikiLink(true, false);
                wikiLink.setUrl(BROKENLINK_URL);
                wikiLink.setDescription(BROKENLINK_DESCRIPTION);
                log.debug("wiki link could not be resolved: " + linkText);
            }

        // Check if it is a custom protocol
        } else if (customProtocolMatcher.find()) {

            if (linkProtocolMap.containsKey(customProtocolMatcher.group(1))) {
                LinkProtocol protocol = linkProtocolMap.get(customProtocolMatcher.group(1));
                wikiLink = new WikiLink(false, true);
                wikiLink.setUrl(protocol.getRealLink(customProtocolMatcher.group(2)));
                wikiLink.setDescription(protocol.getPrefix() + "://" + customProtocolMatcher.group(2));
                log.debug("link resolved to custom protocol: " + linkText);
            } else {
                wikiLink = new WikiLink(true, false);
                wikiLink.setUrl(BROKENLINK_URL);
                wikiLink.setDescription(BROKENLINK_DESCRIPTION);
                log.debug("link resolved to non-existant custom protocol: " + linkText);
            }

        // It must be a stored clear text link, such as [=>Target Name] or [=>Area Name|Target Name]
        // (This can happen if the string [foo=>bar] or [foo=>bar|baz] was stored in the database because the
        //  targets didn't exist at the time of saving)
        } else {

            // Try a WikiWord search in the current or named area
            WikiFile doc = resolveCrossAreaLinkText(currentAreaNumber, linkText);
            if (doc!=null) {

                wikiLink = new WikiLink(false, false);
                wikiLink.setFile(doc);
                wikiLink.setDescription(doc.getName());
                // Indicate that caller should update the wiki text that contains this link
                wikiLink.setRequiresUpdating(true);
                log.debug("resolved wiki word link, this needs updating to the real identifier: " + linkText);

            } else {
                /* TODO: Not sure we should actually implement this..., one of these things that the wiki "designers" got wrong
                // OK, so it's not any recognized URL and we can't find a node with that wikiname
                // Let's assume its a page name and render /Area/WikiLink (but encoded, so it gets transported fully)
                // into the edit page when the user clicks on the link to create the document
                try {
                    String encodedPagename = currentDirectory.getWikiname() + "/" + URLEncoder.encode(linkText, "UTF-8");
                    wikiLink = new WikiLink(null, true, encodedPagename, linkText);
                } catch (UnsupportedEncodingException e) {
                    throw new RuntimeException(e); // Java is so great...
                }
                */
                wikiLink = new WikiLink(true, false);
                wikiLink.setUrl(BROKENLINK_URL);
                wikiLink.setDescription(BROKENLINK_DESCRIPTION);
                log.debug("could not resolve link: " + linkText);
            }
        }
        links.put(linkText, wikiLink);
    }

    private WikiFile resolveCrossAreaLinkText(Long currentAreaNumber, String linkText) {
        Matcher crossLinkMatcher = Pattern.compile(REGEX_WIKILINK_CROSSAREA).matcher(linkText);
        if (crossLinkMatcher.find()) {
            // Try to find the node in the referenced area
            String areaName = crossLinkMatcher.group(1);
            String nodeName = crossLinkMatcher.group(2);
            WikiNode crossLinkArea = wikiNodeDAO.findArea(WikiUtil.convertToWikiName(areaName));
            if (crossLinkArea != null)
                return wikiNodeDAO.findWikiFileInArea(crossLinkArea.getAreaNumber(), WikiUtil.convertToWikiName(nodeName));
        } else {
            // Try the current area
            return wikiNodeDAO.findWikiFileInArea(currentAreaNumber, WikiUtil.convertToWikiName(linkText));
        }
        return null;
    }

}
