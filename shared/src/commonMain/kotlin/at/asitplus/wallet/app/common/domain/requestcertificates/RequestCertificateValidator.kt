package at.asitplus.wallet.app.common.domain.requestcertificates

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
                ?: payload.objectField("sub")?.stringField("id")
                ?: payload.stringField("iss")
        }
}

internal class RequestCertificateValidator(
    private val chainValidator: WrpacCertificateChainValidator = WrpacCertificateChainValidator(),
    private val wrpacRequestX5cValidator: WrpacRequestX5cValidator = WrpacRequestX5cValidator(chainValidator),
    private val wrprcParser: WrprcVerifierInfoParser = WrprcVerifierInfoParser(),
    private val wrprcValidator: WrprcVerifierInfoValidator = WrprcVerifierInfoValidator(chainValidator),
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

        val registrationCertPayloads = wrprcValidator.validateAndExtractPayloads(wrprcParser.parse(verifierInfo))
        Napier.d(
            "validation completed, registration_cert payloads=${registrationCertPayloads.size}",
            tag = tag
        )

        return RequestCertificateValidationResult(
            registrationCertPayloads = registrationCertPayloads,
        )
    }
}

private fun JsonObject.stringField(key: String): String? =
    (this[key] as? JsonPrimitive)?.contentOrNull

private fun JsonObject.objectField(key: String): JsonObject? =
    runCatching { this[key]?.jsonObject }.getOrNull()
