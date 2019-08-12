package com.djrollins.oauthclient

import com.fasterxml.jackson.databind.PropertyNamingStrategy
import com.fasterxml.jackson.databind.annotation.JsonNaming
import com.fasterxml.jackson.module.kotlin.KotlinModule
import org.apache.commons.codec.binary.Hex
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.ApplicationRunner
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.http.HttpEntity
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.client.RestTemplate
import org.springframework.web.client.exchange
import org.springframework.web.client.postForEntity
import org.springframework.web.servlet.config.annotation.EnableWebMvc
import java.util.*
import java.util.logging.Logger
import javax.servlet.http.HttpSession

@EnableWebMvc
@SpringBootApplication
@EnableConfigurationProperties
class OauthClientApplication {

    val log: Logger = Logger.getGlobal()

    @Bean
    fun applicationRunner(): ApplicationRunner {
        return ApplicationRunner { log.info("running!") }
    }

    @Bean
    fun objectMapperBuilder(): Jackson2ObjectMapperBuilder {
        return Jackson2ObjectMapperBuilder()
                .modules(KotlinModule())
    }
}

@Controller
class RestController(private val githubSecrets: GithubSecrets) {

    val restTemplate = RestTemplate()
    val clientId: String = githubSecrets.clientId
    val clientSecret: String = githubSecrets.clientSecret
    val authorizeUrl: String = "https://github.com/login/oauth/authorize"
    val tokenUrl: String = "https://github.com/login/oauth/access_token"
    val apiUrl: String = "https://api.github.com/"
    val host: String = "localhost"

    @Value("\${server.port}")
    lateinit var port: String

    @GetMapping("/authorize")
    fun authorize(@RequestParam code: String, @RequestParam state: String, model: Model, session: HttpSession): String {
        val sessionState: String? = session.getAttribute("state") as String?
        if (!sessionState.equals(state)) {
            return "error"
        }

        val response = restTemplate.postForEntity<Map<String, String>>(tokenUrl, mapOf(
                "grant_type" to "authorization_code",
                "client_id" to clientId,
                "client_secret" to clientSecret,
                "redirect_uri" to "http://$host:8080/authorize",
                "code" to code
        ))

        if (response.statusCode != HttpStatus.OK) {
            return "error"
        }

        session.setAttribute("accessCode", response.body?.get("access_token"))
        return "redirect:/"
    }

    @GetMapping("/")
    fun landingPage(@RequestParam(required = false, defaultValue = "World") name: String, model: Model, session: HttpSession): String {
        val accessCode: String? = session.getAttribute("accessCode") as String?
        if (accessCode.isNullOrBlank()) {
            val bytes = ByteArray(16)
            Random().nextBytes(bytes)
            val state = Hex.encodeHexString(bytes)

            session.setAttribute("state", state)
            val queryParams = "?response_type=code&client_id=$clientId&redirect_url=http://$host/authorize&scope=user public_repo&state=$state"

            return "redirect:$authorizeUrl$queryParams"
        }

        Logger.getGlobal().info(accessCode)

        val response = restTemplate.exchange<List<Repo>>(
                "$apiUrl/user/repos",
                HttpMethod.GET,
                HttpEntity<Void>(httpHeaders("Authorization" to "Bearer $accessCode")),
                mapOf("sort" to "created", "direction" to "desc")
        )

        if (response.statusCode == HttpStatus.UNAUTHORIZED) {
            session.removeAttribute("accessCode")
            return "redirect:/"
        } else {
            model.addAttribute("repos", response.body)
        }

        return "repos"
    }
}

@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy::class)
data class Repo(val name: String, val htmlUrl: String)

fun httpHeaders(vararg headers: Pair<String, String>): HttpHeaders {
    val mappedHeaders: Array<Pair<String, List<String>>> = headers.map { Pair(it.first, listOf(it.second)) }.toTypedArray()
    val backingMap = LinkedMultiValueMap(mapOf(*mappedHeaders))
    return HttpHeaders(backingMap)
}

fun main(args: Array<String>) {
    runApplication<OauthClientApplication>(*args)
}
