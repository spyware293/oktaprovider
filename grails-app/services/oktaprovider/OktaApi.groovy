package oktaprovider

import com.github.scribejava.core.builder.api.DefaultApi20
import groovy.util.logging.Slf4j
import grails.util.Holders

@Slf4j
class OktaApi extends DefaultApi20 {

    private static final String AUTHORIZE_URL = "/oauth2/v1/authorize";
    private static final String REQUEST_TOKEN_URL = "/oauth2/v1/token";

    private String authorizeUrl;
    private String tokenUrl;

    protected OktaApi() {

        this.authorizeUrl = Holders.getGrailsApplication().config.getProperty('grails.plugin.springsecurity.oauth2.providers.okta.authorizeUrl')
        log.info "Okta authorizeUrl = " + this.authorizeUrl

        if (!this.authorizeUrl || this.authorizeUrl == null) {
            throw new MissingPropertyException("Please define authorizeUrl for Okta OAuth2 ('grails.plugin.springsecurity.oauth2.providers.okta.authorizeUrl')");
        }

        this.tokenUrl = Holders.getGrailsApplication().config.getProperty('grails.plugin.springsecurity.oauth2.providers.okta.tokenUrl')
        log.info "Okta tokenUrl = " + this.tokenUrl

        if (!this.tokenUrl || this.tokenUrl == null) {
            throw new MissingPropertyException("Please define tokenUrl for Okta OAuth2 ('grails.plugin.springsecurity.oauth2.providers.okta.tokenUrl')");
        }
    }

    private static class InstanceHolder {
        private static final OktaApi INSTANCE = new OktaApi();
    }

    public static OktaApi instance() {
        return InstanceHolder.INSTANCE;
    }

    public String getAccessTokenEndpoint() {
        this.tokenUrl
    }

    protected String getAuthorizationBaseUrl() {
        this.authorizeUrl
    }

}