//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.alfresco.web.site.servlet.config;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.extensions.config.Config;
import org.springframework.extensions.config.ConfigService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

public class AIMSConfig {
    private static final Log logger = LogFactory.getLog(AIMSConfig.class);
    private boolean enabled;
    private String realm;
    private String resource;
    private String secret;
    private String authServerUrl;
    private String sslRequired;
    private String principalAttribute;

    private String  wellKnownOpenidConfigurationUrl;

    private String  issuerUri;
    private ConfigService configService;
    private Boolean publicClient;

    public AIMSConfig() {
    }

    public void init() {
        Config config = this.configService.getConfig("AIMS");
        this.setEnabled(Boolean.parseBoolean(config.getConfigElement("enabled").getValue()));
        this.setRealm(config.getConfigElementValue("realm"));
        this.setResource(config.getConfigElementValue("resource"));
        this.setAuthServerUrl(config.getConfigElementValue("authServerUrl"));
        this.setSslRequired(config.getConfigElementValue("sslRequired"));
        this.setPublicClient(Boolean.parseBoolean(config.getConfigElement("publicClient").getValue()));
        this.setWellKnownOpenidConfigurationUrl(config.getConfigElementValue("wellKnownOpenidConfigurationUrl"));
        this.setIssuerUri(config.getConfigElementValue("issuerUri"));
        if (this.publicClient) {
            this.setSecret((String)null);
        } else {
            if (StringUtils.isEmpty(config.getConfigElementValue("secret"))) {
                OAuth2Error oauth2Error = new OAuth2Error("Missing secret-key value. Please provide a Secret Key");
                throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
            }

            this.setSecret(config.getConfigElementValue("secret"));
        }

        if (!StringUtils.isEmpty(config.getConfigElementValue("principalAttribute"))) {
            this.setPrincipalAttribute(config.getConfigElementValue("principalAttribute"));
        } else {
            this.setPrincipalAttribute("sub");
        }

    }

    public void setConfigService(ConfigService configService) {
        this.configService = configService;
    }

    private void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return this.enabled;
    }

    public String getRealm() {
        return this.realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public String getWellKnownOpenidConfigurationUrl() {
        return this.wellKnownOpenidConfigurationUrl;
    }

    public void setWellKnownOpenidConfigurationUrl(String wellKnownOpenidConfigurationUrl) {
        this.wellKnownOpenidConfigurationUrl = wellKnownOpenidConfigurationUrl;
    }
    public String getIssuerUri() {
        return this.issuerUri;
    }

    public void setIssuerUri(String issuerUri) {
        this.issuerUri = issuerUri;
    }

    public String getResource() {
        return this.resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public String getAuthServerUrl() {
        return this.authServerUrl;
    }

    public void setAuthServerUrl(String authServerUrl) {
        this.authServerUrl = authServerUrl;
    }

    public String getSslRequired() {
        return this.sslRequired;
    }

    public void setSslRequired(String sslRequired) {
        this.sslRequired = sslRequired;
    }

    public String getSecret() {
        return this.secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getPrincipalAttribute() {
        return this.principalAttribute;
    }

    public void setPrincipalAttribute(String principalAttribute) {
        this.principalAttribute = principalAttribute;
    }

    public Boolean getPublicClient() {
        return this.publicClient;
    }

    public void setPublicClient(Boolean publicClient) {
        this.publicClient = publicClient;
    }
}
