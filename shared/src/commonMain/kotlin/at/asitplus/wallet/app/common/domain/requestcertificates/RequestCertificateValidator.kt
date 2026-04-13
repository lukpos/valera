package at.asitplus.wallet.app.common.domain.requestcertificates

import at.asitplus.openid.RequestParametersFrom
import at.asitplus.wallet.app.common.HttpService
import at.asitplus.wallet.lib.openid.AuthorizationResponsePreparationState
import io.github.aakira.napier.Napier
import kotlinx.serialization.json.JsonObject

internal data class RequestCertificateValidationResult(val registrationCertPayloads: List<JsonObject> = emptyList()) {
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
    private val wrpacRequestValidator: WrpacRequestValidator = WrpacRequestValidator(chainValidator),
    private val wrprcParser: WrprcVerifierInfoParser = WrprcVerifierInfoParser(),
    private val wrprcValidator: WrprcVerifierInfoValidator = WrprcVerifierInfoValidator(chainValidator),
    private val publicRegistrationInfoLoader: PublicRegistrationInfoLoader = PublicRegistrationInfoLoader(httpService)
) {
    private val tag = "RequestCert.Validator"

    suspend fun validate(preparationState: AuthorizationResponsePreparationState): RequestCertificateValidationResult {
        val params = preparationState.request.parameters
        val verifierInfo = params.verifierInfo.orEmpty()
        Napier.d(
            "requestType=${preparationState.request::class.simpleName}, " +
                "client_id=${params.clientId}, " +
                "response_mode=${params.responseMode}, " +
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

        val wrpacValidation = wrpacRequestValidator.validate(preparationState)
        if (!wrpacValidation.isValid) {
            Napier.e("WRPAC request validation failed; aborting request-certificate processing.", tag = tag)
            return RequestCertificateValidationResult()
        }
        wrpacValidation.wrpIdentifier?.let {
            Napier.d("Resolved wrpIdentifier from request x5c: $it", tag = tag)
        }

        val parsedVerifierInfo = wrprcParser.parse(verifierInfo)
        val registrationCertPayloads = if (parsedVerifierInfo.isNotEmpty()) {
            Napier.d("WRPRC present in verifier_info; validating registration certificate.", tag = tag)
            wrprcValidator.validateAndExtractPayloads(parsedVerifierInfo)
        } else {
            Napier.i("WRPRC missing in verifier_info; falling back to public registration info.", tag = tag)
            loadRegistrationInfo(preparationState, wrpacValidation.wrpIdentifier)
        }
        Napier.d("Validation completed; registration_cert payloads=${registrationCertPayloads.size}", tag = tag)

        return RequestCertificateValidationResult(
            registrationCertPayloads = registrationCertPayloads,
        )
    }

    private suspend fun loadRegistrationInfo(
        preparationState: AuthorizationResponsePreparationState,
        wrpIdentifier: String?
    ): List<JsonObject> {
        val requestUrl = requestSourceUrl(preparationState)
        if (requestUrl == null) {
            Napier.w("Public registration info fallback skipped because the service URL is unavailable.", tag = tag)
            return emptyList()
        }

        return publicRegistrationInfoLoader.loadForRequestSource(
            requestUrl = requestUrl,
            wrpIdentifier = wrpIdentifier
        )
    }
}

private fun requestSourceUrl(preparationState: AuthorizationResponsePreparationState): String? =
    when (val request = preparationState.request) {
        is RequestParametersFrom.Uri -> request.url.toString()
        is RequestParametersFrom.Json -> request.parent?.toString()
        is RequestParametersFrom.JwsSigned -> request.parent?.toString()
        else -> null
    }
