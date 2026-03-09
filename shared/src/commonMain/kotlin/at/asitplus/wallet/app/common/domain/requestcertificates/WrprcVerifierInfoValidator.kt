package at.asitplus.wallet.app.common.domain.requestcertificates

import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.jws.VerifyJwsSignature
import io.github.aakira.napier.Napier
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.JsonObject

internal class WrprcVerifierInfoValidator(
    private val chainValidator: WrpacCertificateChainValidator,
) {
    private val tag = "WrprcVerifierInfoValidator[WRPRC]"

    suspend fun validateAndExtractPayloads(entries: List<ParsedWrprcVerifierInfo>): List<JsonObject> {
        val payloads = mutableListOf<JsonObject>()
        Napier.d("validating entries=${entries.size}", tag = tag)

        entries.forEach { entry ->
            Napier.d(
                "entry[${entry.index}] start, " +
                        "typ='${entry.jws.header.type}', alg='${entry.jws.header.algorithm.identifier}', " +
                        "x5cCount=${entry.jws.header.certificateChain?.size ?: 0}",
                tag = tag
            )
            if (!validateHeader(entry.index, entry.jws)) {
                return@forEach
            }

            val leafCertificate = chainValidator.validateMandatoryChain(
                entry.jws.header.certificateChain,
                source = "WRPRC verifier_info[${entry.index}] (registration_cert) x5c"
            ) ?: return@forEach

            if (!validateSignature(entry.index, entry.jws, leafCertificate)) {
                return@forEach
            }

            Napier.d(
                "entry[${entry.index}] accepted, payloadSummary=" +
                        buildPayloadSummary(entry.jws.payload),
                tag = tag
            )
            payloads += entry.jws.payload
        }

        Napier.d("accepted payloads=${payloads.size}", tag = tag)
        return payloads
    }

    private fun validateHeader(index: Int, jws: JwsSigned<JsonObject>): Boolean {
        if (jws.header.type != "rc-wrp+jwt") {
            Napier.e(
                "verifier_info[$index] (registration_cert) has invalid typ in JWS header. " +
                        "expected='rc-wrp+jwt', actual='${jws.header.type}'",
                tag = tag
            )
            return false
        }
        if (jws.header.algorithm.identifier != "ES256") {
            Napier.e(
                "verifier_info[$index] (registration_cert) has invalid alg in JWS header. " +
                        "expected='ES256', actual='${jws.header.algorithm.identifier}'",
                tag = tag
            )
            return false
        }
        Napier.d("header checks passed for entry[$index].", tag = tag)
        return true
    }

    private suspend fun validateSignature(
        index: Int,
        jws: JwsSigned<JsonObject>,
        leafCertificate: X509Certificate,
    ): Boolean {
        val jwsAlgorithm = jws.header.algorithm
        if (jwsAlgorithm !is JwsAlgorithm.Signature) {
            Napier.e("verifier_info[$index] (registration_cert) uses unsupported JWS algorithm.", tag = tag)
            return false
        }

        return runCatching {
            VerifyJwsSignature().invoke(jws, leafCertificate.decodedPublicKey.getOrThrow()).getOrThrow()
            Napier.d("signature validation passed for entry[$index].", tag = tag)
            true
        }.getOrElse {
            Napier.e("verifier_info[$index] (registration_cert) signature validation failed.", it, tag = tag)
            false
        }
    }

    private fun buildPayloadSummary(payload: JsonObject): String {
        val name = (payload["name"] as? JsonPrimitive)?.contentOrNull
        val issuer = (payload["iss"] as? JsonPrimitive)?.contentOrNull
        val subjectId = runCatching { payload["sub"]?.jsonObject?.get("id") as? JsonPrimitive }
            .getOrNull()
            ?.contentOrNull
        return "name=$name, iss=$issuer, sub.id=$subjectId"
    }
}
