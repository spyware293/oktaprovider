security {
    oauth2 {
        providers {
            okta {
                successUri = "/oauth2/okta/success"
                failureUri = "/oauth2/okta/failure"
                callback = "/oauth2/okta/callback"
                api_key = "changeme_apikey"
                api_secret = "changeme_apisecret"
                scopes = 'email profile openid'
            }
        }
    }
}
