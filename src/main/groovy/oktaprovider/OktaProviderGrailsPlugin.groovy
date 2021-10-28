package oktaprovider

import grails.plugin.springsecurity.ReflectionUtils
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.oauth2.SpringSecurityOauth2BaseService
import grails.plugin.springsecurity.oauth2.exception.OAuth2Exception
import grails.plugins.*
import groovy.util.logging.Slf4j

@Slf4j
class OktaProviderGrailsPlugin extends Plugin {

    def loadAfter = ['spring-security-oauth2']

    // the version or versions of Grails the plugin is designed for
    def grailsVersion = "3.3.3 > *"
    // resources that are excluded from plugin packaging
    def pluginExcludes = [
            "grails-app/views/error.gsp"
    ]

    def title = "Spring Security Oauth2 Okta" // Headline display name of the plugin
    def author = "Andrew Hughes"
    def authorEmail = "andrew.hughes@toptal.com"
    def description = '''\
Plugin adds Okta support for OAuth in Grails
'''
    def profiles = ['web']

    // URL to the plugin's documentation
    def documentation = "http://grails.org/plugin/spring-security-oauth2-okta"


    Closure doWithSpring() {
        {->
            ReflectionUtils.application = grailsApplication
            if (grailsApplication.warDeployed) {
                SpringSecurityUtils.resetSecurityConfig()
            }
            SpringSecurityUtils.application = grailsApplication

            // Check if there is an SpringSecurity configuration
            def coreConf = SpringSecurityUtils.securityConfig
            boolean printStatusMessages = (coreConf.printStatusMessages instanceof Boolean) ? coreConf.printStatusMessages : true
            if (!coreConf || !coreConf.active) {
                if (printStatusMessages) {
                    println("ERROR: There is no SpringSecurity configuration or SpringSecurity is disabled")
                    println("ERROR: Stopping configuration of SpringSecurity Oauth2")
                }
                return
            }

            if (printStatusMessages) {
                println("Configuring Spring Security OAuth2 Okta plugin...")
            }

            SpringSecurityUtils.loadSecondaryConfig('DefaultOAuth2OktaConfig')

            if (printStatusMessages) {
                println("... finished configuring Spring Security OAuth2 Okta Plugin\n")
            }
        }
    }


    void doWithApplicationContext() {
        log.trace("doWithApplicationContext")
        SpringSecurityOauth2BaseService oAuth2BaseService = applicationContext.getBean('springSecurityOauth2BaseService', SpringSecurityOauth2BaseService)
        OktaOAuth2Service oktaOAuth2Service = applicationContext.getBean('oktaOAuth2Service', OktaOAuth2Service)
        try {
            oAuth2BaseService.registerProvider(oktaOAuth2Service)
        }
        catch (OAuth2Exception e) {
            log.error("There was an oAuth2Exception", e)
            log.error("OAuth2 Github not loaded")
        }
    }
}
