/*
 * JBoss, Home of Professional Open Source
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.jboss.seam.wiki.test.plugin;

import org.dbunit.operation.DatabaseOperation;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.wiki.core.dao.WikiNodeDAO;
import org.jboss.seam.wiki.core.feeds.FeedDAO;
import org.jboss.seam.wiki.core.model.FeedEntry;
import org.jboss.seam.wiki.core.model.WikiDirectory;
import org.jboss.seam.wiki.core.model.WikiDocument;
import org.jboss.seam.wiki.plugin.forum.TopicHome;
import org.jboss.seam.wiki.test.util.DBUnitSeamTest;
import org.testng.annotations.Test;

public class TopicHomeTests extends DBUnitSeamTest {

    protected void prepareDBUnitOperations() {
        beforeTestOperations.add(
            new DataSetOperation("org/jboss/seam/wiki/test/WikiBaseData.dbunit.xml", DatabaseOperation.CLEAN_INSERT)
        );
        beforeTestOperations.add(
            new DataSetOperation("org/jboss/seam/wiki/test/ForumData.dbunit.xml", DatabaseOperation.INSERT)
        );
    }

    @Test
    public void newTopic() throws Exception {

        final String conversationId = new FacesRequest() {

            protected void updateModelValues() throws Exception {
                WikiNodeDAO nodeDAO = (WikiNodeDAO)getInstance("wikiNodeDAO");
                WikiDirectory forumDir = nodeDAO.findWikiDirectory(102l);
                Contexts.getPageContext().set("currentDirectory", forumDir);
            }

            protected void invokeApplication() throws Exception {
                TopicHome home = (TopicHome)getInstance("topicHome");
                home.newTopic();
            }
        }.run();

        new FacesRequest() {

            protected void beforeRequest() {
                setParameter("cid", conversationId);
            }

            protected void updateModelValues() throws Exception {
                WikiNodeDAO nodeDAO = (WikiNodeDAO)getInstance("wikiNodeDAO");
                WikiDirectory forumDir = nodeDAO.findWikiDirectory(102l);
                Contexts.getPageContext().set("currentDirectory", forumDir);
            }

            protected void invokeApplication() throws Exception {
                TopicHome home = (TopicHome)getInstance("topicHome");

                home.getInstance().setName("New Topic");
                home.setFormContent("This is a new topic.");

                assert invokeMethod("#{topicHome.persist}") == null;
            }

            protected void renderResponse() throws Exception {
                Long newId = (Long)getValue("#{topicHome.instance.id}");

                WikiNodeDAO nodeDAO = (WikiNodeDAO)getInstance("wikiNodeDAO");
                WikiDocument newTopic = nodeDAO.findWikiDocument(newId);

                assert newTopic.getAreaNumber().equals(100l);

                FeedDAO feedDAO = (FeedDAO)getInstance("feedDAO");
                FeedEntry fe = feedDAO.findFeedEntry(newTopic);
                assert fe.getTitle().equals("[Seam Users] New Topic");

                assert newTopic.getHeaderMacrosString().contains("forumPosting");
                assert newTopic.getFooterMacrosString().contains("forumReplies");
                assert newTopic.getContent().equals("This is a new topic.");
                assert !newTopic.isNameAsTitle();
                assert newTopic.isEnableCommentForm();
                assert newTopic.isEnableComments();
                assert newTopic.isEnableCommentsOnFeeds();
            }
        }.run();

    }

    @Test
    public void newStickyTopic() throws Exception {

        loginAdmin();

        final String conversationId = new FacesRequest() {

            protected void updateModelValues() throws Exception {
                WikiNodeDAO nodeDAO = (WikiNodeDAO)getInstance("wikiNodeDAO");
                WikiDirectory forumDir = nodeDAO.findWikiDirectory(102l);
                Contexts.getPageContext().set("currentDirectory", forumDir);
            }

            protected void invokeApplication() throws Exception {
                TopicHome home = (TopicHome)getInstance("topicHome");
                home.newTopic();
            }
        }.run();

        new FacesRequest() {

            protected void beforeRequest() {
                setParameter("cid", conversationId);
            }

            protected void updateModelValues() throws Exception {
                WikiNodeDAO nodeDAO = (WikiNodeDAO)getInstance("wikiNodeDAO");
                WikiDirectory forumDir = nodeDAO.findWikiDirectory(102l);
                Contexts.getPageContext().set("currentDirectory", forumDir);
            }

            protected void invokeApplication() throws Exception {
                TopicHome home = (TopicHome)getInstance("topicHome");

                home.getInstance().setName("New Topic");
                home.setFormContent("This is a new topic.");
                home.setSticky(true);

                assert invokeMethod("#{topicHome.persist}") == null;
            }

            protected void renderResponse() throws Exception {
                Long newId = (Long)getValue("#{topicHome.instance.id}");

                WikiNodeDAO nodeDAO = (WikiNodeDAO)getInstance("wikiNodeDAO");
                WikiDocument newTopic = nodeDAO.findWikiDocument(newId);

                assert newTopic.getAreaNumber().equals(100l);

                FeedDAO feedDAO = (FeedDAO)getInstance("feedDAO");
                FeedEntry fe = feedDAO.findFeedEntry(newTopic);
                assert fe.getTitle().equals("[Seam Users] New Topic");

                assert newTopic.getHeaderMacrosString().contains("forumStickyPosting");
                assert newTopic.getFooterMacrosString().contains("forumReplies");
                assert newTopic.getContent().equals("This is a new topic.");
                assert !newTopic.isNameAsTitle();
                assert newTopic.isEnableCommentForm();
                assert newTopic.isEnableComments();
                assert newTopic.isEnableCommentsOnFeeds();
            }
        }.run();
    }

    @Test
    public void newClosedTopic() throws Exception {

        loginAdmin();

        final String conversationId = new FacesRequest() {

            protected void updateModelValues() throws Exception {
                WikiNodeDAO nodeDAO = (WikiNodeDAO)getInstance("wikiNodeDAO");
                WikiDirectory forumDir = nodeDAO.findWikiDirectory(102l);
                Contexts.getPageContext().set("currentDirectory", forumDir);
            }

            protected void invokeApplication() throws Exception {
                TopicHome home = (TopicHome)getInstance("topicHome");
                home.newTopic();
            }
        }.run();

        new FacesRequest() {

            protected void beforeRequest() {
                setParameter("cid", conversationId);
            }

            protected void updateModelValues() throws Exception {
                WikiNodeDAO nodeDAO = (WikiNodeDAO)getInstance("wikiNodeDAO");
                WikiDirectory forumDir = nodeDAO.findWikiDirectory(102l);
                Contexts.getPageContext().set("currentDirectory", forumDir);
            }

            protected void invokeApplication() throws Exception {
                TopicHome home = (TopicHome)getInstance("topicHome");

                home.getInstance().setName("New Topic");
                home.setFormContent("This is a new topic.");
                home.getInstance().setEnableComments(false);

                assert invokeMethod("#{topicHome.persist}") == null;
            }

            protected void renderResponse() throws Exception {
                Long newId = (Long)getValue("#{topicHome.instance.id}");

                WikiNodeDAO nodeDAO = (WikiNodeDAO)getInstance("wikiNodeDAO");
                WikiDocument newTopic = nodeDAO.findWikiDocument(newId);

                assert newTopic.getAreaNumber().equals(100l);

                FeedDAO feedDAO = (FeedDAO)getInstance("feedDAO");
                FeedEntry fe = feedDAO.findFeedEntry(newTopic);
                assert fe.getTitle().equals("[Seam Users] New Topic");

                assert newTopic.getHeaderMacrosString().contains("forumPosting");
                assert newTopic.getFooterMacrosString().contains("forumReplies");
                assert newTopic.getContent().equals("This is a new topic.");
                assert !newTopic.isNameAsTitle();
                assert !newTopic.isEnableComments();
            }
        }.run();
    }

    private void loginAdmin() throws Exception {
        new FacesRequest() {
           protected void invokeApplication() throws Exception {
              setValue("#{identity.username}", "admin");
              setValue("#{identity.password}", "admin");
              invokeAction("#{identity.login}");
              assert getValue("#{identity.loggedIn}").equals(true);
           }
        }.run();
    }


}