package org.jboss.seam.wiki.core.action;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.wiki.core.model.WikiUpload;
import org.jboss.seam.wiki.core.model.WikiDirectory;
import org.jboss.seam.wiki.core.upload.UploadType;
import org.jboss.seam.wiki.core.upload.UploadTypes;
import org.jboss.seam.wiki.core.upload.Uploader;
import org.jboss.seam.wiki.core.upload.editor.UploadEditor;

import javax.faces.application.FacesMessage;
import java.util.Date;
import java.util.Map;

@Name("uploadHome")
@Scope(ScopeType.CONVERSATION)
public class UploadHome extends NodeHome<WikiUpload, WikiDirectory> {

    /* -------------------------- Context Wiring ------------------------------ */

    @In(required = false)
    Uploader uploader;

    @In
    Map<String, UploadType> uploadTypes;

    /* -------------------------- Internal State ------------------------------ */

    protected UploadEditor uploadEditor;
    private String tagString;

    /* -------------------------- Basic Overrides ------------------------------ */

    @Override
    public Class<WikiUpload> getEntityClass() {
        return WikiUpload.class;
    }

    @Override
    public WikiUpload findInstance() {
        return getWikiNodeDAO().findWikiUpload((Long)getId());
    }

    @Override
    protected WikiDirectory findParentNode(Long parentNodeId) {
        return getEntityManager().find(WikiDirectory.class, parentNodeId);
    }

    @Override
    public WikiUpload afterNodeCreated(WikiUpload ignoredNode) {
        if (uploader == null || uploader.getUpload() == null) {
            throw new RuntimeException("No uploader found for create");
        }
        getLog().debug("initializing with new uploaded file: " + uploader.getFilename());
        WikiUpload upload = uploader.getUpload();
        upload = super.afterNodeCreated(upload);
        initUploadEditor(upload);
        return upload;
    }

    @Override
    public WikiUpload afterNodeFound(WikiUpload upload) {
        upload = super.afterNodeFound(upload);

        getLog().debug("initializing with existing upload '" + upload + "' and content type: " + upload.getContentType());

        tagString = upload.getTagsCommaSeparated();

        initUploadEditor(upload);
        return upload;
    }

    /* -------------------------- Custom CUD ------------------------------ */

    @Override
    protected boolean preparePersist() {
        return uploadEditor.preparePersist();
    }

    @Override
    protected boolean beforePersist() {
        // Set createdOn date _now_
        getInstance().setCreatedOn(new Date());

        // Tags
        getInstance().setTagsCommaSeparated(tagString);

        return uploadEditor.beforePersist();
    }

    @Override
    protected boolean beforeUpdate() {
        // Tags
        getInstance().setTagsCommaSeparated(tagString);

        return uploadEditor.beforeUpdate();
    }

    @Override
    protected boolean beforeRemove() {
        return uploadEditor.beforeRemove();
    }

    /* -------------------------- Internal Methods ------------------------------ */

    private void initUploadEditor(WikiUpload instance) {
        if (uploader != null && uploader.getUpload() != null) {
            uploadEditor = uploader.getUploadHandler().createEditor(uploader.getUpload());
        } else {
            UploadType uploadType = uploadTypes.get(instance.getContentType());
            if (uploadType == null) {
                getLog().debug("couldn't find upload handler for content type, using generic handler and editor");
                uploadType = uploadTypes.get(UploadTypes.GENERIC_UPLOAD_TYPE);
            }
            uploadEditor = uploadType.getUploadHandler().createEditor(instance);
        }
    }

    /* -------------------------- Messages ------------------------------ */

    @Override
    protected void createdMessage() {
        getFacesMessages().addFromResourceBundleOrDefault(
                FacesMessage.SEVERITY_INFO,
                "lacewiki.msg.Upload.Persist",
                "File '{0}' has been saved.",
                getInstance().getName()
        );
    }

    @Override
    protected void updatedMessage() {
        getFacesMessages().addFromResourceBundleOrDefault(
                FacesMessage.SEVERITY_INFO,
                "lacewiki.msg.Upload.Update",
                "File '{0}' has been updated.",
                getInstance().getName()
        );
    }

    @Override
    protected void deletedMessage() {
        getFacesMessages().addFromResourceBundleOrDefault(
                FacesMessage.SEVERITY_INFO,
                "lacewiki.msg.Upload.Delete",
                "File '{0}' has been deleted.",
                getInstance().getName()
        );
    }

    protected void uploadUpdatedMessage() {
        getFacesMessages().addFromResourceBundleOrDefault(
                FacesMessage.SEVERITY_INFO,
                "lacewiki.msg.uploadEdit.UpdateUpload",
                "File '{0}' has been uploaded.",
                uploader.getFilename()
        );
    }

    /* -------------------------- Public Features ------------------------------ */

    public UploadEditor getUploadEditor() {
        if (uploadEditor == null) initUploadEditor(getInstance());
        return uploadEditor;
    }

    public void uploadUpdateInstance() {
        if (uploader.uploadUpdateInstance(getInstance(), true) != null) {
            uploadUpdatedMessage();
        }
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
