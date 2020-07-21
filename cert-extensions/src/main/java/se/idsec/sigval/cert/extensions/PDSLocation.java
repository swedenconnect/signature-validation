/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package se.idsec.sigval.cert.extensions;

/**
 *
 * @author stefan
 */
public class PDSLocation {
    String lang;
    String url;

    public PDSLocation() {
    }

    public PDSLocation(String lang, String url) {
        this.lang = lang;
        this.url = url;
    }

    public String getLang() {
        return lang;
    }

    public void setLang(String lang) {
        this.lang = lang;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
            
}
