/*
 * JBoss, Home of Professional Open Source
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.jboss.seam.wiki.core.action;

import org.jboss.seam.Component;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.wiki.core.action.prefs.CommentsPreferences;
import org.jboss.seam.wiki.core.action.prefs.DocumentEditorPreferences;
import org.jboss.seam.wiki.core.action.prefs.WikiPreferences;
import org.jboss.seam.wiki.core.feeds.FeedDAO;
import org.jboss.seam.wiki.core.feeds.FeedEntryManager;
import org.jboss.seam.wiki.core.engine.WikiLinkResolver;
import org.jboss.seam.wiki.core.engine.MacroWikiTextRenderer;
import org.jboss.seam.wiki.core.model.WikiDirectory;
import org.jboss.seam.wiki.core.model.WikiDocument;
import org.jboss.seam.wiki.core.model.WikiFile;
import org.jboss.seam.wiki.core.model.FeedEntry;
import org.jboss.seam.wiki.preferences.PreferenceProvider;

import static javax.faces.application.FacesMessage.SEVERITY_INFO;
import java.util.*;

@Name("documentHome")
@Scope(ScopeType.CONVERSATION)
public class DocumentHome extends NodeHome<WikiDocument, WikiDirectory> {

    /* -------------------------- Context Wiring ------------------------------ */

    @In(required = false)
    private DocumentHistory documentHistory;
    @In
    private FeedDAO feedDAO;

    /* -------------------------- Internal State ------------------------------ */

    private WikiDocument historicalCopy;
    private Boolean minorRevision;
    private String formContent;
    private String tagString;
    Set<WikiFile> linkTargets;
    private boolean enabledPreview = false;
    private boolean pushOnFeeds = false;
    private boolean pushOnSiteFeed = false;
    private boolean isOnSiteFeed = false;
    private List<WikiFile> historicalFiles;
    private Long numOfHistoricalFiles = 0l;

    /* -------------------------- Basic Overrides ------------------------------ */

    @Override
    public Class<WikiDocument> getEntityClass() {
        return WikiDocument.class;
    }

    @Override
    public WikiDocument findInstance() {
        return getWikiNodeDAO().findWikiDocument((Long)getId());
    }

    @Override
    protected WikiDirectory findParentNode(Long parentNodeId) {
        return getEntityManager().find(WikiDirectory.class, parentNodeId);
    }

    @Override
    public WikiDocument afterNodeCreated(WikiDocument doc) {
        doc = super.afterNodeCreated(doc);

        outjectDocumentAndDirectory(doc, getParentNode());
        return doc;
    }

    @Override
    public WikiDocument beforeNodeEditNew(WikiDocument doc) {
        doc = super.beforeNodeEditNew(doc);

        doc.setEnableComments( ((CommentsPreferences)Component.getInstance("commentsPreferences")).getEnableByDefault() );

        return doc;
    }

    @Override
    public WikiDocument afterNodeFound(WikiDocument doc) {
        doc = super.afterNodeFound(doc);

        findHistoricalFiles(doc);
        syncMacros(doc.getAreaNumber(), doc);
        outjectDocumentAndDirectory(doc, getParentNode());

        return doc;
    }

    @Override
    public WikiDocument beforeNodeEditFound(WikiDocument doc) {
        doc = super.beforeNodeEditFound(doc);

        // Rollback to historical revision?
        if (documentHistory != null && documentHistory.getSelectedHistoricalFile() != null) {
            getLog().debug("rolling back to revision: " + documentHistory.getSelectedHistoricalFile().getRevision());
            // TODO: Avoid cast, make history polymorphic
            doc.rollback((WikiDocument)documentHistory.getSelectedHistoricalFile());
        }

        isOnSiteFeed = feedDAO.isOnSiteFeed(doc);
        tagString = doc.getTagsCommaSeparated();

        return doc;
    }

    /* -------------------------- Custom CUD ------------------------------ */

    @Override
    protected boolean beforePersist() {
        // Sync document content
        syncFormContentToInstance(getParentNode());
        syncLinks();
        syncTags();

        // Set createdOn date _now_
        getInstance().setCreatedOn(new Date());

        // Make a copy
        historicalCopy = new WikiDocument();
        historicalCopy.flatCopy(getInstance(), true);

        return true;
    }

    @Override
    public String persist() {
        String outcome = super.persist();

        // Create feed entries (needs identifiers assigned, so we run after persist())
        if (outcome != null && isPushOnFeeds()) {
            getLog().debug("creating feed entries on parent dirs - and on site feed: " + isPushOnSiteFeed());
            isOnSiteFeed = isPushOnSiteFeed();

            FeedEntry feedEntry =
                    ((FeedEntryManager)Component.getInstance(getFeedEntryManagerName())).createFeedEntry(getInstance());
            feedDAO.createFeedEntry(getParentNode(), getInstance(), feedEntry, isPushOnSiteFeed());

            getEntityManager().flush();
            setPushOnFeeds(false);
            setPushOnSiteFeed(false);
        }

        return outcome;
    }

    @Override
    protected boolean beforeUpdate() {

        // Sync document content
        syncFormContentToInstance(getParentNode());
        syncLinks();
        syncTags();

        // Update feed entries
        if (isPushOnFeeds()) {
            isOnSiteFeed = isPushOnSiteFeed();

            FeedEntry feedEntry = feedDAO.findFeedEntry(getInstance());
            if (feedEntry == null) {
                getLog().debug("creating feed entries on parent dirs - and on site feed: " + isPushOnSiteFeed());
                feedEntry = ((FeedEntryManager)Component.getInstance(getFeedEntryManagerName())).createFeedEntry(getInstance());
                feedDAO.createFeedEntry(getParentNode(), getInstance(), feedEntry, isPushOnSiteFeed());
            } else {
                getLog().debug("updating feed entries on parent dirs - and on site feed: " + isPushOnSiteFeed());
                ((FeedEntryManager)Component.getInstance(getFeedEntryManagerName())).updateFeedEntry(feedEntry, getInstance());
                feedDAO.updateFeedEntry(getParentNode(), getInstance(), feedEntry, isPushOnSiteFeed());
            }

            setPushOnFeeds(false);
            setPushOnSiteFeed(false);
        }

        // Feeds should not be removed by a maintenance thread: If there
        // is no activity on the site, feeds shouldn't be empty but show the last updates.
        WikiPreferences wikiPrefs = (WikiPreferences) Component.getInstance("wikiPreferences");
        Calendar oldestDate = GregorianCalendar.getInstance();
        oldestDate.add(Calendar.DAY_OF_YEAR, -wikiPrefs.getPurgeFeedEntriesAfterDays().intValue());
        feedDAO.purgeOldFeedEntries(oldestDate.getTime());

        // Write history log and prepare a new copy for further modification
        if (!isMinorRevision()) {
            if (historicalCopy == null)
                throw new IllegalStateException("Call getFormContent() once to create a historical revision");
            getLog().debug("storing the historical copy as a new revision");
            historicalCopy.setId(getInstance().getId());
            historicalCopy.setLastModifiedBy(getCurrentUser());
            getWikiNodeDAO().persistHistoricalFile(historicalCopy);
            getInstance().incrementRevision();
            // New historical copy in conversation
            historicalCopy = new WikiDocument();
            historicalCopy.flatCopy(getInstance(), true);

            // Reset form
            setMinorRevision(
                (Boolean)((DocumentEditorPreferences)Component
                    .getInstance("docEditorPreferences")).getProperties().get("minorRevisionEnabled")
            );
        }

        return true;
    }

    @Override
    protected boolean prepareRemove() {

        // Remove feed entry before removing document
        feedDAO.removeFeedEntry(
            feedDAO.findFeeds(getInstance()),
            feedDAO.findFeedEntry(getInstance())
        );

        return super.prepareRemove();
    }

    @Override
    protected boolean beforeRemove() {

        // Delete preferences of this node
        PreferenceProvider provider = (PreferenceProvider) Component.getInstance("preferenceProvider");
        provider.deleteInstancePreferences(getInstance());


        return super.beforeRemove();
    }

    /* TODO: Implement node moving
    @Override
    protected void afterNodeMoved(WikiDirectory oldParent, WikiDirectory newParent) {
        // Update view
        syncFormContentToInstance(oldParent); // Resolve existing links in old directory
        syncInstanceToFormContent(newParent); // Now update the form, effectively re-rendering the links
        Contexts.getConversationContext().set("currentDirectory", newParent);
    }
    */

    /* -------------------------- Messages ------------------------------ */

    @Override
    protected void createdMessage() {
        getFacesMessages().addFromResourceBundleOrDefault(
                SEVERITY_INFO,
                "lacewiki.msg.Document.Persist",
                "Document '{0}' has been saved.",
                getInstance().getName()
        );
    }

    @Override
    protected void updatedMessage() {
        getFacesMessages().addFromResourceBundleOrDefault(
                SEVERITY_INFO,
                "lacewiki.msg.Document.Update",
                "Document '{0}' has been updated.",
                getInstance().getName()
        );
    }

    @Override
    protected void deletedMessage() {
        getFacesMessages().addFromResourceBundleOrDefault(
                SEVERITY_INFO,
                "lacewiki.msg.Document.Delete",
                "Document '{0}' has been deleted.",
                getInstance().getName()
        );
    }

    /* -------------------------- Internal Methods ------------------------------ */

    protected void findHistoricalFiles(WikiDocument doc) {
        getLog().debug("Finding number of historical files for: " + doc);
        numOfHistoricalFiles= getWikiNodeDAO().findNumberOfHistoricalFiles(doc);
        if (isHistoricalFilesPresent()) {
            historicalFiles = getWikiNodeDAO().findHistoricalFiles(doc);
        }
    }

    // Wiki text parser and plugins need this
    protected void outjectDocumentAndDirectory(WikiDocument doc, WikiDirectory dir) {
        if (isPageRootController()) {
            if (doc != null) {
                getLog().debug("setting current document: " + doc);
                Contexts.getPageContext().set("currentDocument", doc);
            }
            if (dir != null) {
                getLog().debug("setting current directory: " + dir);
                Contexts.getPageContext().set("currentDirectory", dir);
            }
        }
    }

    private void syncLinks() {
        if (linkTargets != null) getInstance().setOutgoingLinks(linkTargets);
    }

    private void syncTags() {
        getInstance().setTagsCommaSeparated(tagString);
    }

    private void syncMacros(Long areaNumber, WikiDocument doc) {
        if (doc.getHeader() != null) {
            MacroWikiTextRenderer renderer = MacroWikiTextRenderer.renderMacros(areaNumber, doc.getHeader());
            doc.setHeaderMacros(renderer.getMacros());
            doc.setHeaderMacrosString(renderer.getMacrosString());
        }
        if (doc.getContent() != null) {
            MacroWikiTextRenderer renderer = MacroWikiTextRenderer.renderMacros(areaNumber, doc.getContent());
            doc.setContentMacros(renderer.getMacros());
            doc.setContentMacrosString(renderer.getMacrosString());
        }
        if (doc.getFooter() != null) {
            MacroWikiTextRenderer renderer = MacroWikiTextRenderer.renderMacros(areaNumber, doc.getFooter());
            doc.setFooterMacros(renderer.getMacros());
            doc.setFooterMacrosString(renderer.getMacrosString());
        }
    }

    private void syncFormContentToInstance(WikiDirectory dir) {
        if (formContent != null) {
            getLog().debug("sync form content to instance");
            WikiLinkResolver wikiLinkResolver = (WikiLinkResolver)Component.getInstance("wikiLinkResolver");
            linkTargets = new HashSet<WikiFile>();
            getInstance().setContent(
                wikiLinkResolver.convertToWikiProtocol(linkTargets, dir.getAreaNumber(), formContent)
            );
            syncMacros(dir.getAreaNumber(), getInstance());
        }
    }

    private void syncInstanceToFormContent(WikiDirectory dir) {
        getLog().debug("sync instance to form");
        WikiLinkResolver wikiLinkResolver = (WikiLinkResolver)Component.getInstance("wikiLinkResolver");
        formContent = wikiLinkResolver.convertFromWikiProtocol(dir.getAreaNumber(), getInstance().getContent());
        if (historicalCopy == null) {
            getLog().debug("making a history copy of the document");
            historicalCopy = new WikiDocument();
            historicalCopy.flatCopy(getInstance(), true);
        }
    }

    protected String getFeedEntryManagerName() {
        return "wikiDocumentFeedEntryManager";
    }

    /* -------------------------- Public Features ------------------------------ */

    public String getFormContent() {
        // Load the document content and resolve links
        if (formContent == null) syncInstanceToFormContent(getParentNode());
        return formContent;
    }

    public void setFormContent(String formContent) {
        this.formContent = formContent;
        if (formContent != null) {
            syncFormContentToInstance(getParentNode());
        }
    }

    public boolean isMinorRevision() {
        // Lazily initalize preferences
        if (minorRevision == null)
            minorRevision = (Boolean)((DocumentEditorPreferences)Component
                    .getInstance("docEditorPreferences")).getProperties().get("minorRevisionEnabled");
        return minorRevision;
    }
    public void setMinorRevision(boolean minorRevision) { this.minorRevision = minorRevision; }

    public boolean isEnabledPreview() {
        return enabledPreview;
    }

    public void setEnabledPreview(boolean enabledPreview) {
        this.enabledPreview = enabledPreview;
        syncFormContentToInstance(getParentNode());
    }

    public boolean isOnSiteFeed() {
        return isOnSiteFeed;
    }

    public boolean isPushOnFeeds() {
        return pushOnFeeds;
    }

    public void setPushOnFeeds(boolean pushOnFeeds) {
        this.pushOnFeeds = pushOnFeeds;
    }

    public boolean isPushOnSiteFeed() {
        return pushOnSiteFeed;
    }

    public void setPushOnSiteFeed(boolean pushOnSiteFeed) {
        this.pushOnSiteFeed = pushOnSiteFeed;
    }

    public void setShowPluginPrefs(boolean showPluginPrefs) {
        Contexts.getPageContext().set("showPluginPreferences", showPluginPrefs);
    }

    // TODO: Move this into WikiTextEditor.java
    public boolean isShowPluginPrefs() {
        Boolean showPluginPrefs = (Boolean)Contexts.getPageContext().get("showPluginPreferences");
        return showPluginPrefs != null && showPluginPrefs;
    }

    public boolean isHistoricalFilesPresent() {
        return numOfHistoricalFiles != null && numOfHistoricalFiles> 0;
    }

    public List<WikiFile> getHistoricalFiles() {
        return historicalFiles;
    }

    public String getTagString() {
        return tagString;
    }

    public void setTagString(String tagString) {
        this.tagString = tagString;
    }

    public boolean isTagInTagString(String tag) {
        return tag != null && getTagString() != null && getTagString().contains(tag);
    }

}
