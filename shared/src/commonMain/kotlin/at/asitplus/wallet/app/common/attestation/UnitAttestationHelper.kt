package at.asitplus.wallet.app.common.attestation

import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.dsl.PREFERRED
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.wallet.app.common.Configuration
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.SignerBasedKeyMaterial
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.JwsHeaderIdentifierFun
import at.asitplus.wallet.lib.jws.SignJwt
import io.ktor.client.HttpClient
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

class UnitAttestationHelper(ENDPOINT: Flow<String>) {
    val KS_ALIAS_WUA = "ALIAS_WUA"
    val ENDPOINT_UNIT = ENDPOINT.map { "$it/api/v1/unit" }

    val httpClient = HttpClient()

    suspend fun requestUnitAttestation(
        instanceAttestation: JwsSigned<JsonWebToken>,
        pop: JwsSigned<JsonWebToken>
    ): JwsSigned<KeyAttestationJwt> {
        PlatformSigningProvider.deleteSigningKey(KS_ALIAS_WUA)
        val holderKey = createHolderKey(KS_ALIAS_WUA)

        val body = UnitAttestationRequest(
            token = instanceAttestation.serialize(),
            keys = listOf(holderKey.publicKey.toJsonWebKey()),
            storageType = "LOCAL_NATIVE",
            proof = pop.serialize()
        )
        val response = httpClient.post(ENDPOINT_UNIT.first()) {
            contentType(ContentType.Application.Json)
            setBody(vckJsonSerializer.encodeToString(body))
        }

        return JwsSigned.deserialize<KeyAttestationJwt>(
            it = response.bodyAsText(), deserializationStrategy = KeyAttestationJwt.serializer()
        ).getOrThrow()
    }

    suspend fun buildProofOfPossession(
        unitAttestation: JwsSigned<KeyAttestationJwt>,
        type: String,
        payload: JsonWebToken
    ) =
        PlatformSigningProvider.getSignerForKey(KS_ALIAS_WUA).getOrThrow().let {
            SignJwt<JsonWebToken>(
                HolderKeyMaterial(it), JwsHeaderUnitAttestationPop(unitAttestation.serialize())
            ).invoke(
                type,
                payload,
                JsonWebToken.serializer(),
            ).getOrThrow()
        }

    private suspend fun createHolderKey(alias: String): Signer {
        PlatformSigningProvider.let { provider ->
            return provider.getSignerForKey(alias).getOrElse {
                provider.createSigningKey(alias = alias) {
                    ec {
                        curve = ECCurve.SECP_256_R_1
                        purposes {
                            keyAgreement = true
                            signing = true
                        }
                    }
                    hardware {
                        backing = PREFERRED
                        protection {
                            factors {
                                biometry = true
                            }
                            timeout = Configuration.BIOMETRIC_TIMEOUT
                        }
                    }
                }.getOrThrow()
            }
        }
    }
}

@Serializable
data class UnitAttestationRequest(
    @SerialName("token") val token: String,
    @SerialName("proof") val proof: String,
    @SerialName("keys") val keys: List<JsonWebKey>,
    @SerialName("storage_type") val storageType: String,
)

class JwsHeaderUnitAttestationPop(val wua: String) : JwsHeaderIdentifierFun {
    override suspend operator fun invoke(
        it: JwsHeader,
        keyMaterial: KeyMaterial,
    ) = it.copy(keyId = "0", keyAttestation = wua, jsonWebKey = keyMaterial.jsonWebKey)
}


class HolderKeyMaterial(
    signer: Signer,
) : SignerBasedKeyMaterial(signer) {
    override suspend fun getCertificate(): X509Certificate? = null
}