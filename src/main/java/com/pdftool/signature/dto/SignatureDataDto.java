package com.pdftool.signature.dto;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;

public class SignatureDataDto {

    private String name;
    private String location;
    private String reason;
    private String modified;
    private Collection<? extends Certificate> certList = new ArrayList<>();
    private String contentHash;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public String getModified() {
        return modified;
    }

    public void setModified(String modified) {
        this.modified = modified;
    }

    public Collection<? extends Certificate> getCertList() {
        return certList;
    }

    public void setCertList(Collection<? extends Certificate> certList) {
        this.certList = certList;
    }

    public void setContentHash(String contentHash) {
        this.contentHash = contentHash;
    }

    public String getContentHash() {
        return contentHash;
    }
}
