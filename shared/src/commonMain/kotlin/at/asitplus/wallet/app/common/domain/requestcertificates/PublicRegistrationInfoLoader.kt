package at.asitplus.wallet.app.common.domain.requestcertificates

import at.asitplus.wallet.app.common.HttpService
import io.github.aakira.napier.Napier
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.http.URLBuilder
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull

internal interface RegistrarBaseUrlResolver {
    fun resolveForRequestSource(requestUrl: String): String?
}

internal class StaticRegistrarBaseUrlResolver(
    private val registrarBaseUrl: String = "http://10.0.2.2:5000",
) : RegistrarBaseUrlResolver {
    override fun resolveForRequestSource(requestUrl: String): String? = registrarBaseUrl
}

internal class PublicRegistrationInfoLoader(
    private val httpService: HttpService,
    private val registrarBaseUrlResolver: RegistrarBaseUrlResolver = StaticRegistrarBaseUrlResolver(),
) {
    private val tag = "PublicRegistrationInfoLoader[WRPRC]"

    suspend fun loadForRequestSource(
        requestUrl: String,
    ): List<JsonObject> {
        val registrarBaseUrl = registrarBaseUrlResolver.resolveForRequestSource(requestUrl)
        if (registrarBaseUrl == null) {
            Napier.w("Could not resolve registrar base URL for request source $requestUrl.", tag = tag)
            return emptyList()
        }
        Napier.i(
            "WRPRC missing. Looking up public registration info via registrar $registrarBaseUrl for request source $requestUrl",
            tag = tag
        )

        val wrps = runCatching {
            httpService.buildHttpClient().use { httpClient ->
                httpClient.get("$registrarBaseUrl/api/public/wrps").body<List<RegistrarPublicWrpDto>>()
            }
        }.getOrElse {
            Napier.e("Could not load public WRP list from registrar $registrarBaseUrl.", it, tag = tag)
            return emptyList()
        }

        val resolvedService = resolveServiceRegistration(requestUrl, wrps)
        if (resolvedService == null) {
            Napier.w("No matching public WRP service registration found for request source $requestUrl.", tag = tag)
            return emptyList()
        }

        Napier.i(
            "Loading public registration info for wrp_id=${resolvedService.wrpIdentifier}, service_uri=${resolvedService.serviceUri}",
            tag = tag
        )
        val registrationInfoUrl = URLBuilder("$registrarBaseUrl/api/public/wrps/${resolvedService.wrpIdentifier}/registration-info")
            .apply {
                parameters.append("serviceUri", resolvedService.serviceUri)
            }
            .buildString()

        val registrationInfo = runCatching {
            httpService.buildHttpClient().use { httpClient ->
                httpClient.get(registrationInfoUrl).body<RegistrarRegistrationInfoDto>()
            }
        }.getOrElse {
            Napier.e("Could not load registration info from $registrationInfoUrl.", it, tag = tag)
            return emptyList()
        }

        Napier.i(
            "Public registration info loaded for wrp_id=${registrationInfo.wrpIdentifier}, service_uri=${registrationInfo.serviceUri}, intendedUses=${registrationInfo.intendedUses.size}",
            tag = tag
        )
        Napier.d("Registration info payload: $registrationInfo", tag = tag)

        return listOf(
            buildJsonObject {
                put("iss", JsonPrimitive(registrationInfo.wrpIdentifier))
                put("sub", JsonPrimitive(registrationInfo.wrpIdentifier))
                registrationInfo.displayName?.takeIf { it.isNotBlank() }?.let { put("name", JsonPrimitive(it)) }
                put("registry_uri", JsonPrimitive(registrarBaseUrl.trimEnd('/')))
                put(
                    "srv_description",
                    buildJsonArray {
                        registrationInfo.displayName
                            ?.takeIf { it.isNotBlank() }
                            ?.let { displayName ->
                                add(
                                    buildJsonArray {
                                        add(
                                            buildJsonObject {
                                                put("lang", JsonPrimitive("en"))
                                                put("value", JsonPrimitive(displayName))
                                            }
                                        )
                                    }
                                )
                            }
                    }
                )
                registrationInfo.intendedUses.firstNotNullOfOrNull { it.intendedUseIdentifier }
                    ?.let { put("intended_use_id", JsonPrimitive(it)) }
                registrationInfo.intendedUses.firstNotNullOfOrNull { it.privacyPolicy.singlePolicyUriOrNull() }
                    ?.let { put("privacy_policy", JsonPrimitive(it)) }
                put("credentials", registrationInfo.firstCredentialArrayOrEmpty())
            }
        )
    }

    private fun resolveServiceRegistration(
        requestUrl: String,
        wrps: List<RegistrarPublicWrpDto>,
    ): ResolvedServiceRegistration? {
        val requestOrigin = runCatching {
            val url = URLBuilder(requestUrl)
            val portSuffix = url.port.takeIf { it != url.protocol.defaultPort }?.let { ":$it" }.orEmpty()
            "${url.protocol.name}://${url.host}$portSuffix"
        }.getOrNull()

        val candidates = wrps.flatMap { wrp ->
            wrp.services.map { service ->
                ResolvedServiceRegistration(
                    wrpIdentifier = wrp.wrpIdentifier,
                    serviceUri = service.serviceUri,
                )
            }
        }

        return candidates.firstOrNull { it.serviceUri == requestUrl }
            ?: candidates.firstOrNull { requestUrl.startsWith(it.serviceUri) }
            ?: requestOrigin?.let { origin ->
                candidates.firstOrNull { it.serviceUri == origin || origin.startsWith(it.serviceUri) }
            }
    }

    private fun RegistrarRegistrationInfoDto.firstCredentialArrayOrEmpty(): JsonArray =
        intendedUses.firstNotNullOfOrNull { intendedUse ->
            when (val credential = intendedUse.credential) {
                null -> null
                is JsonArray -> credential.takeIf { it.isNotEmpty() }
                else -> buildJsonArray { add(credential) }
            }
        } ?: buildJsonArray { }

    private fun JsonElement?.singlePolicyUriOrNull(): String? = when (this) {
        is JsonObject -> (this["policyURI"] as? JsonPrimitive)?.contentOrNull?.takeIf { it.isNotBlank() }
        is JsonArray -> firstNotNullOfOrNull { element ->
            (element as? JsonObject)?.get("policyURI")?.let { policyUri ->
                (policyUri as? JsonPrimitive)?.contentOrNull?.takeIf { it.isNotBlank() }
            }
        }
        else -> null
    }

    private data class ResolvedServiceRegistration(
        val wrpIdentifier: String,
        val serviceUri: String,
    )
}
