package oktaprovider

import com.github.scribejava.core.model.OAuth2AccessToken
import grails.plugin.springsecurity.oauth2.token.OAuth2SpringToken
import groovy.transform.CompileStatic

@CompileStatic
class OktaOauth2SpringToken extends OAuth2SpringToken {

    private String email
    final String providerName

    OktaOauth2SpringToken(OAuth2AccessToken accessToken, String email, String providerId) {
        super(accessToken)
        this.email = email
        this.providerName = providerId
    }

    String getSocialId() {
        return email
    }

    String getScreenName() {
        return email
    }

}