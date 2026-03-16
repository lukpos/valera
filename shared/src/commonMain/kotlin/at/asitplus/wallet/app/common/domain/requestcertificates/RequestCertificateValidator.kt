package at.asitplus.wallet.app.common.domain.requestcertificates

import at.asitplus.openid.RequestParametersFrom
import at.asitplus.wallet.app.common.HttpService
import at.asitplus.wallet.lib.openid.AuthorizationResponsePreparationState
import io.github.aakira.napier.Napier
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject

internal data class RequestCertificateValidationResult(
    val registrationCertPayloads: List<JsonObject> = emptyList(),
) {
    fun preferredRecipientDisplay(): String? =
        registrationCertPayloads.firstNotNullOfOrNull { payload ->
            payload.stringField("name")
                ?: payload.stringField("sub")
                ?: payload.stringField("iss")
        }
}

internal class RequestCertificateValidator(
    httpService: HttpService,
    private val chainValidator: WrpacCertificateChainValidator = WrpacCertificateChainValidator(),
    private val wrpacRequestX5cValidator: WrpacRequestX5cValidator = WrpacRequestX5cValidator(chainValidator),
    private val wrprcParser: WrprcVerifierInfoParser = WrprcVerifierInfoParser(),
    private val wrprcValidator: WrprcVerifierInfoValidator = WrprcVerifierInfoValidator(chainValidator),
    private val publicRegistrationInfoLoader: PublicRegistrationInfoLoader = PublicRegistrationInfoLoader(httpService),
) {
    private val tag = "RequestCertificateValidator[WRPAC/WRPRC]"

    suspend fun validate(
        preparationState: AuthorizationResponsePreparationState,
    ): RequestCertificateValidationResult {
        val params = preparationState.request.parameters
        val verifierInfo = params.verifierInfo.orEmpty()
        Napier.d(
            "requestType=${preparationState.request::class.simpleName}, " +
                    "client_id=${params.clientId}, response_mode=${params.responseMode}, " +
                    "verifier_info_count=${verifierInfo.size}",
            tag = tag
        )
        if (verifierInfo.isNotEmpty()) {
            Napier.d(
                "verifier_info formats=" +
                        verifierInfo.mapIndexed { idx, info -> "[$idx]=${info.format}" }.joinToString(", "),
                tag = tag
            )
        }

        wrpacRequestX5cValidator.validate(preparationState)

        val parsedVerifierInfo = wrprcParser.parse(verifierInfo)
        val registrationCertPayloads = if (parsedVerifierInfo.isNotEmpty()) {
            Napier.d("WRPRC present in verifier_info. Validating embedded registration certificate.", tag = tag)
            wrprcValidator.validateAndExtractPayloads(parsedVerifierInfo)
        } else {
            Napier.i("WRPRC missing in verifier_info. Falling back to public registration info.", tag = tag)
            loadRegistrationInfo(preparationState)
        }
        Napier.d(
            "validation completed, registration_cert payloads=${registrationCertPayloads.size}",
            tag = tag
        )

        return RequestCertificateValidationResult(
            registrationCertPayloads = registrationCertPayloads,
        )
    }

    private suspend fun loadRegistrationInfo(
        preparationState: AuthorizationResponsePreparationState,
    ): List<JsonObject> {
        val requestUrl = requestSourceUrl(preparationState)
        if (requestUrl == null) {
            Napier.w("Public registration info fallback skipped because the originating service URL is not available.", tag = tag)
            return emptyList()
        }

        return publicRegistrationInfoLoader.loadForRequestSource(requestUrl)
    }
}

private fun requestSourceUrl(preparationState: AuthorizationResponsePreparationState): String? =
    when (val request = preparationState.request) {
        is RequestParametersFrom.Uri -> request.url.toString()
        is RequestParametersFrom.Json -> request.parent?.toString()
        is RequestParametersFrom.JwsSigned -> request.parent?.toString()
        else -> null
    }

private fun JsonObject.stringField(key: String): String? =
    (this[key] as? JsonPrimitive)?.contentOrNull

private fun JsonObject.objectField(key: String): JsonObject? =
    runCatching { this[key]?.jsonObject }.getOrNull()
