package org.jboss.seam.wiki.plugin.forum;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.*;
import org.jboss.seam.annotations.web.RequestParameter;
import org.jboss.seam.core.Conversation;
import org.jboss.seam.core.Events;
import org.jboss.seam.international.Messages;
import org.jboss.seam.wiki.core.action.DocumentHome;
import org.jboss.seam.wiki.core.model.WikiDirectory;
import org.jboss.seam.wiki.core.model.WikiDocument;
import org.jboss.seam.wiki.core.model.WikiDocumentDefaults;

import static javax.faces.application.FacesMessage.SEVERITY_INFO;

@Name("topicHome")
@Scope(ScopeType.CONVERSATION)
public class TopicHome extends DocumentHome {

    @In
    WikiDirectory currentDirectory;

    private boolean showForm = false;
    private boolean sticky = false;

    /* -------------------------- Basic Overrides ------------------------------ */

    @Override
    protected boolean isPageRootController() {
        return false;
    }

    @Override
    public Class<WikiDocument> getEntityClass() {
        return WikiDocument.class;
    }

    @Override
    public void create() {
        super.create();
        setParentNodeId(currentDirectory.getId());
    }

    @Override
    public WikiDocument afterNodeCreated(WikiDocument doc) {
        WikiDocument newTopic = super.afterNodeCreated(doc);

        WikiDocumentDefaults newTopicDefaults =
                new WikiDocumentDefaults() {
                    public String getDefaultName() {
                        return Messages.instance().get("forum.label.NewTopic");
                    }
                    public String[] getDefaultHeaderMacros() {
                        return new String[] { "clearBackground", "hideControls", "hideComments",
                                              "hideTags", "hideCreatorHistory", "disableContentMacros", "forumPosting" };
                    }
                    public String getDefaultContent() {
                        return Messages.instance().get("lacewiki.msg.wikiTextEditor.EditThisTextPreviewUpdatesAutomatically");
                    }

                    public String[] getDefaultFooterMacros() {
                        return new String[] { "forumReplies" };
                    }
                    public void setDefaults(WikiDocument newTopic) {
                        newTopic.setNameAsTitle(false);
                        newTopic.setEnableComments(true);
                        newTopic.setEnableCommentForm(true);
                        newTopic.setEnableCommentsOnFeeds(true);
                    }
                };
        newTopic.setDefaults(newTopicDefaults);

        setPushOnFeeds(true);

        return newTopic;
    }

    @Override
    protected boolean beforePersist() {
        if (isSticky())
            getInstance().setHeader(
                getInstance().getHeader().replaceAll("forumPosting", "forumStickyPosting")
            );
        return super.beforePersist();
    }

    @Override
    public String persist() {
        String outcome = super.persist();
        if (outcome != null) {
            endConversation();
        }
        return null; // Prevent navigation
    }

    @Override
    public String update() {
        String outcome = super.update();
        if (outcome != null) endConversation();
        return null; // Prevent navigation
    }

    @Override
    public String remove() {
        String outcome = super.remove();
        if (outcome != null) endConversation();
        return null; // Prevent navigation
    }

    /* -------------------------- Messages ------------------------------ */

    protected void createdMessage() {
        getFacesMessages().addFromResourceBundleOrDefault(
                SEVERITY_INFO,
                "forum.msg.Topic.Persist",
                "Topic '{0}' has been saved.",
                getInstance().getName()
        );
    }

    protected void updatedMessage() {
        getFacesMessages().addFromResourceBundleOrDefault(
                SEVERITY_INFO,
                "forum.msg.Topic.Update",
                "Topic '{0}' has been updated.",
                getInstance().getName()
        );
    }

    protected void deletedMessage() {
        getFacesMessages().addFromResourceBundleOrDefault(
                SEVERITY_INFO,
                "forum.msg.Topic.Delete",
                "Topic '{0}' has been deleted.",
                getInstance().getName()
        );
    }

    /* -------------------------- Internal Methods ------------------------------ */

    private void endConversation() {
        showForm = false;
        Conversation.instance().end();
        getEntityManager().clear(); // Need to force re-read in the topic list refresh
        Events.instance().raiseEvent("Forum.topicListRefresh");
    }

    protected String getFeedEntryManagerName() {
        return "forumTopicFeedEntryManager";
    }

    /* -------------------------- Public Features ------------------------------ */

    public boolean isShowForm() {
        return showForm;
    }

    public void setShowForm(boolean showForm) {
        this.showForm = showForm;
    }

    public boolean isSticky() {
        return sticky;
    }

    public void setSticky(boolean sticky) {
        this.sticky = sticky;
    }

    @Begin(flushMode = FlushModeType.MANUAL, join = true)
    public void newTopic() {
        setEdit(true);
        showForm = true;
    }

    public void cancel() {
        endConversation();
    }

    @RequestParameter("showTopicForm")
    public void showTopicForm(Boolean requestParam) {
        if (requestParam != null && requestParam && !showForm) {
            getLog().debug("request parameter sets topic form visible, starts conversation");
            Conversation.instance().begin(true, false);
            Conversation.instance().changeFlushMode(FlushModeType.MANUAL);
            newTopic();
        }
    }

}
