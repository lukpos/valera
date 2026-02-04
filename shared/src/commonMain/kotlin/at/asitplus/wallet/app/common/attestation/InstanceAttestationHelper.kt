package at.asitplus.wallet.app.common.attestation

import at.asitplus.attestation.supreme.AttestationChallenge
import at.asitplus.attestation.supreme.AttestationClient
import at.asitplus.attestation.supreme.createCsr
import at.asitplus.openid.ClientNonceResponse
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants.CLIENT_ATTESTATION_POP_JWT
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.Url
import io.ktor.http.contentType
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.ExperimentalTime

class InstanceAttestationHelper(ENDPOINT: Flow<String>) {
    val ENDPOINT_CHALLENGE = ENDPOINT.map { "$it/api/v1/challenge" }
    val ENDPOINT_INSTANCE = ENDPOINT.map { "$it/api/v1/instance" }
    val ENDPOINT_NONCE = ENDPOINT.map { "$it/api/v1/nonce" }


    val KS_ALIAS_WIA = "ALIAS_WIA"

    val httpClient = HttpClient()
    val client = AttestationClient(httpClient)
    suspend fun createAttestationSigner(challenge: AttestationChallenge, alias: String) =
        PlatformSigningProvider.createSigningKey(alias) {
            ec {}
            hardware {
                attestation {
                    this.challenge = challenge.nonce
                }
            }
        }.getOrThrow()

    private suspend fun getAttestationChallenge() = client.getChallenge(Url(ENDPOINT_CHALLENGE.first()))
    private suspend fun getNonce() = runCatching {
        vckJsonSerializer.decodeFromString<ClientNonceResponse>(
            httpClient.get(url = Url(urlString = ENDPOINT_NONCE.first())).bodyAsText()
        ).clientNonce
    }


    suspend fun requestInstanceAttestation(versionName: String) =
        getAttestationChallenge().getOrThrow().let { challenge ->
            PlatformSigningProvider.deleteSigningKey(KS_ALIAS_WIA)
            val instanceAttestationSigner = createAttestationSigner(challenge, KS_ALIAS_WIA)
            val csr = instanceAttestationSigner.createCsr(challenge).getOrThrow()
            val request = InstanceAttestationRequest(
                csr = csr.encodeToDer(),
                walletSolutionVersion = versionName
            )
            val response = httpClient.post(ENDPOINT_INSTANCE.first()) {
                contentType(ContentType.Application.Json)
                setBody(vckJsonSerializer.encodeToString(request))
            }
            JwsSigned.deserialize<JsonWebToken>(
                it = response.bodyAsText(),
                deserializationStrategy = JsonWebToken.serializer(),
            ).getOrThrow()
        }

    suspend fun buildProofOfPossession(nonce: String? = null): JwsSigned<JsonWebToken> =
        PlatformSigningProvider.getSignerForKey(KS_ALIAS_WIA).getOrThrow().let {
            BuildInstanceAttestationProofJwt(
                SignJwt(HolderKeyMaterial(it), headerModifier = JwsHeaderNone()),
                lifetime = 1.minutes,
                audience = null,
                nonce = nonce ?: getNonce().getOrNull()
            )
        }
}


object BuildInstanceAttestationProofJwt {
    @OptIn(ExperimentalTime::class)
    suspend operator fun invoke(
        signJwt: SignJwtFun<JsonWebToken>,
        audience: String? = null,
        nonce: String? = null,
        lifetime: Duration = 60.minutes,
        clockSkew: Duration = 5.minutes,
    ) = signJwt(
        CLIENT_ATTESTATION_POP_JWT,
        JsonWebToken(
            audience = audience,
            nonce = nonce,
            issuedAt = Clock.System.now() - clockSkew,
        ),
        JsonWebToken.Companion.serializer(),
    ).getOrThrow()
}


@Serializable
data class InstanceAttestationRequest(
    @SerialName("csr") val csr: ByteArray,
    @SerialName("wallet_solution_version") val walletSolutionVersion: String
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as InstanceAttestationRequest

        if (!csr.contentEquals(other.csr)) return false
        if (walletSolutionVersion != other.walletSolutionVersion) return false

        return true
    }

    override fun hashCode(): Int {
        var result = csr.contentHashCode()
        result = 31 * result + walletSolutionVersion.hashCode()
        return result
    }
}