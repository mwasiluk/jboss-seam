package org.jboss.seam.wiki.core.model;

import org.hibernate.validator.Length;
import org.jboss.seam.wiki.core.nestedset.NestedSetNode;
import org.jboss.seam.wiki.core.nestedset.NestedSetNodeInfo;
import org.jboss.seam.wiki.core.nestedset.query.NestedSetDuplicator;

import javax.persistence.*;
import java.io.Serializable;

@Entity
@Table(name = "WIKI_DIRECTORY")
@org.hibernate.annotations.ForeignKey(name = "FK_WIKI_DIRECTORY_NODE_ID")
@org.hibernate.annotations.OnDelete(action = org.hibernate.annotations.OnDeleteAction.CASCADE)
public class WikiDirectory extends WikiNode implements NestedSetNode<WikiDirectory>, Serializable {

    @Column(name = "DESCRIPTION", nullable = true)
    @Length(min = 0, max = 512)
    private String description;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "DEFAULT_FILE_ID", nullable = true, unique = true)
    @org.hibernate.annotations.ForeignKey(name = "FK_WIKI_DIRECTORY_DEFAULT_FILE_ID")
    @org.hibernate.annotations.LazyToOne(org.hibernate.annotations.LazyToOneOption.NO_PROXY)
    private WikiFile defaultFile;

    @OneToOne(fetch = FetchType.LAZY, mappedBy = "directory", cascade = CascadeType.PERSIST)
    @org.hibernate.annotations.LazyToOne(org.hibernate.annotations.LazyToOneOption.NO_PROXY)
    private Feed feed;

    @Embedded
    private NestedSetNodeInfo<WikiDirectory> nodeInfo;

    public WikiDirectory() {
        nodeInfo = new NestedSetNodeInfo<WikiDirectory>(this);
    }

    public WikiDirectory(String name) {
        super(name);
        nodeInfo = new NestedSetNodeInfo<WikiDirectory>(this);
    }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    /**
     * Careful calling this, it always returns the assigned File, even if
     * the user has a lower access level. Hibernate filters don't filter many-to-one
     * because if we have the id, we get the instance.
     *
     * @return WikiFile The assigned default starting file of this directory
     */
    public WikiFile getDefaultFile() { return defaultFile; }
    public void setDefaultFile(WikiFile defaultFile) { this.defaultFile = defaultFile; }

    public Feed getFeed() { return feed; }
    public void setFeed(Feed feed) { this.feed = feed; }

    public void flatCopy(WikiDirectory original, boolean copyLazyProperties) {
        super.flatCopy(original, copyLazyProperties);
        this.description = original.description;
        this.nodeInfo = original.nodeInfo;
    }

    public NestedSetNodeInfo<WikiDirectory> getNodeInfo() {
        return nodeInfo;
    }

    public NestedSetNodeInfo<WikiDirectory> getParentNodeInfo() {
        if (getParent() != null && WikiDirectory.class.isAssignableFrom(getParent().getClass()))
            return ((WikiDirectory)getParent()).getNodeInfo();
        return null;
    }

    public String[] getPropertiesForGroupingInQueries() {
        return new String[]{
            "version", "parent",
            "areaNumber", "name", "wikiname", "createdBy", "createdOn",
            "lastModifiedBy", "lastModifiedOn", "readAccessLevel", "writeAccessLevel", "writeProtected",
            "defaultFile", "description"
        };
    }

    public String[] getLazyPropertiesForGroupingInQueries() {
        return new String[0];
    }

    public String getPermURL(String suffix) {
        return "/" + getId() + suffix;
    }

    public String getWikiURL() {
        if (getArea() == null) return "/"; // Wiki ROOT
        if (getArea().getWikiname().equals(getWikiname())) {
            return "/" + getArea().getWikiname();
        } else {
            return "/" + getArea().getWikiname() + "/" + getWikiname();
        }
    }

    public String toString() {
        return "Directory (" + getId() + "): " + getName();
    }
}
