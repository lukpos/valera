package at.asitplus.wallet.app.common.domain.requestcertificates

import at.asitplus.iso.sha256
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.wallet.lib.openid.AuthorizationResponsePreparationState
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString

internal class WrpacRequestX5cValidator(
    private val chainValidator: WrpacCertificateChainValidator = WrpacCertificateChainValidator(),
) {
    private val tag = "WrpacRequestX5cValidator[WRPAC]"

    fun validate(preparationState: AuthorizationResponsePreparationState): String? {
        val params = preparationState.request.parameters
        return when (val request = preparationState.request) {
            is RequestParametersFrom.DcApiSigned<*> -> {
                Napier.d(
                    "validating mandatory request x5c, " +
                            "count=${request.jwsSigned.header.certificateChain?.size ?: 0}",
                    tag = tag
                )
                debugX509HashBinding(params.clientId, request.jwsSigned.header.certificateChain)
                chainValidator.validateMandatoryChain(
                    request.jwsSigned.header.certificateChain,
                    source = "WRPAC request x5c"
                )
                null
            }

            is RequestParametersFrom.JwsSigned<*> -> {
                Napier.d(
                    "validating optional request x5c, " +
                            "count=${request.jwsSigned.header.certificateChain?.size ?: 0}",
                    tag = tag
                )
                request.jwsSigned.header.certificateChain?.let {
                    debugX509HashBinding(params.clientId, it)
                    chainValidator.validateOptionalChain(it, source = "WRPAC request x5c")
                    null
                }
            }

            else -> null
        }
    }

    private fun debugX509HashBinding(clientId: String?, chain: CertificateChain?) {
        if (chain.isNullOrEmpty()) {
            Napier.d("x509_hash debug skipped, request x5c missing.", tag = tag)
            return
        }
        if (clientId.isNullOrBlank()) {
            Napier.d("x509_hash debug skipped, client_id missing.", tag = tag)
            return
        }
        if (!clientId.startsWith("x509_hash:")) {
            Napier.d("x509_hash debug skipped, client_id is '$clientId'.", tag = tag)
            return
        }

        val expectedHash = clientId.removePrefix("x509_hash:")
        val calculatedHash = runCatching {
            chain.first().encodeToDer().sha256().encodeToString(Base64UrlStrict)
        }.getOrElse {
            Napier.e("x509_hash calculation from request x5c[0] failed.", it, tag = tag)
            return
        }

        Napier.d("x509_hash expected(client_id)=$expectedHash", tag = tag)
        Napier.d("x509_hash calculated(request x5c[0])=$calculatedHash", tag = tag)
        if (calculatedHash == expectedHash) {
            Napier.d("x509_hash binding passed.", tag = tag)
        } else {
            Napier.e("x509_hash binding FAILED.", tag = tag)
        }
    }
}
