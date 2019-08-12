package com.djrollins.oauthclient

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.stereotype.Component

@Component
@ConfigurationProperties(prefix = "github")
class GithubSecrets {
    lateinit var clientId: String
    lateinit var clientSecret: String
}