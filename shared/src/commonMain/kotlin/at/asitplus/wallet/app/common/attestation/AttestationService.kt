package at.asitplus.wallet.app.common.attestation

import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import at.asitplus.wallet.app.common.BuildContext
import at.asitplus.wallet.app.common.data.SettingsRepository
import io.github.aakira.napier.Napier
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.firstOrNull
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

class AttestationService(
    private val config: SettingsRepository,
    private val buildContext: BuildContext,
) {
    val instanceAttestationHelper = InstanceAttestationHelper(config.walletProviderHost)
    val unitAttestationHelper = UnitAttestationHelper(config.walletProviderHost)
    var bufferedInstanceAttestation = MutableStateFlow<JwsSigned<JsonWebToken>?>(null)
    var bufferedUnitAttestation = MutableStateFlow<JwsSigned<KeyAttestationJwt>?>(null)

    suspend fun preloadAttestation() {
        Napier.d("AttestationService: Preload attestation")
        requestInstanceAttestation().let {
            bufferedInstanceAttestation.emit(it)
        }
        requestUnitAttestation().let {
            bufferedUnitAttestation.emit(it)
        }
    }

    suspend fun getInstanceAttestation(): JwsSigned<JsonWebToken> =
        requestInstanceAttestation().let { instanceAttestation ->
            bufferedInstanceAttestation.emit(null)
            instanceAttestation
        }

    suspend fun getInstanceAttestationPop(nonce: String? = null) =
        instanceAttestationHelper.buildProofOfPossession(nonce)

    suspend fun getUnitAttestation(ttl: Duration, type: String, payload: JsonWebToken) =
        requestUnitAttestation(ttl).let { unitAttestation ->
            bufferedUnitAttestation.emit(null)
            unitAttestationHelper.buildProofOfPossession(unitAttestation, type, payload)
        }


    fun getWalletProviderHost() = config.walletProviderHost
    fun setWalletProviderHost(host: String) = config.set(walletProviderHost = host)

    private suspend fun requestInstanceAttestation(): JwsSigned<JsonWebToken> {
        bufferedInstanceAttestation.firstOrNull()?.let { buffer ->
            if ((buffer.payload.expiration)?.let { it > Clock.System.now() + 10.seconds } == true) {
                Napier.d("AttestationService: Use buffered instance attestation")
                return buffer
            }
        }

        Napier.d("AttestationService: Request new instance attestation")
        val instanceAttestation = instanceAttestationHelper.requestInstanceAttestation(buildContext.versionName)
        bufferedInstanceAttestation.emit(instanceAttestation)
        return instanceAttestation
    }

    private suspend fun requestUnitAttestation(
        ttl: Duration = 2678400.seconds
    ): JwsSigned<KeyAttestationJwt> {
        bufferedUnitAttestation.firstOrNull()?.let { buffer ->
            if ((buffer.payload.expiration)?.let { it > Clock.System.now() + ttl } == true) {
                Napier.d("AttestationService: Use buffered unit attestation")
                return buffer
            }
        }

        Napier.d("AttestationService: Request new unit attestation")

        val instanceAttestation = requestInstanceAttestation()
        val pop = instanceAttestationHelper.buildProofOfPossession()

        return unitAttestationHelper.requestUnitAttestation(instanceAttestation, pop)
    }


}