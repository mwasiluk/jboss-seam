/*
 * JBoss, Home of Professional Open Source
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package org.jboss.seam.wiki.core.model;

import org.hibernate.validator.Length;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name = "USER_PROFILE")
@org.hibernate.annotations.BatchSize(size = 20)
public class UserProfile {

    @Id
    @GeneratedValue(generator = "wikiSequenceGenerator")
    @Column(name = "USER_PROFILE_ID")
    private Long id;

    @Version
    @Column(name = "OBJ_VERSION", nullable = false)
    protected int version;

    @Column(name = "CREATED_ON", nullable = false, updatable = false)
    private Date createdOn = new Date();

    @Length(min = 0, max = 1000)
    @Column(name = "BIO", nullable = true)
    private String bio;

    @Length(min = 0, max = 1000)
    @Column(name = "WEBSITE", nullable = true)
    private String website;

    @Length(min = 0, max = 255)
    @Column(name = "LOCATION", nullable = true)
    private String location;

    @Length(min = 0, max = 1000)
    @Column(name = "OCCUPATION", nullable = true)
    private String occupation;

    @Length(min = 0, max = 1000)
    @Column(name = "SIGNATURE", nullable = true)
    private String signature;

    // SchemaExport needs length.. MySQL has "tinyblob", "mediumblob" and other such nonsense types
    @Lob
    @Column(name = "IMAGE_DATA", nullable = true, length = 200000)
    @Basic(fetch = FetchType.LAZY) // Lazy loaded through bytecode instrumentation
    private byte[] image;

    @Column(name = "IMAGE_CONTENT_TYPE", nullable = true, length = 255)
    private String imageContentType;

    public UserProfile() {}

    // Immutable properties

    public Long getId() { return id; }
    public Integer getVersion() { return version; }
    public Date getCreatedOn() { return createdOn; }

    // Mutable properties

    public String getBio() {
        return bio;
    }

    public void setBio(String bio) {
        this.bio = bio.length() > 0 ? bio : null;
    }

    public String getWebsite() {
        return website;
    }

    public void setWebsite(String website) {
        this.website = website.length() > 0 ? website : null;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location.length() > 0 ? location : null;
    }

    public String getOccupation() {
        return occupation;
    }

    public void setOccupation(String occupation) {
        this.occupation = occupation.length() > 0 ? occupation : null;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature.length() > 0 ? signature : null;
    }

    public byte[] getImage() {
        return image;
    }

    public void setImage(byte[] image) {
        this.image = image;
    }

    public String getImageContentType() {
        return imageContentType;
    }

    public void setImageContentType(String imageContentType) {
        this.imageContentType = imageContentType;
    }
}
