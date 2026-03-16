package ui.viewmodels

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.navigation.toRoute
import at.asitplus.catchingUnwrapped
import at.asitplus.wallet.app.common.WalletMain
import domain.BuildAuthenticationConsentPageFromAuthenticationRequestUriUseCase
import io.github.aakira.napier.Napier
import kotlinx.coroutines.launch
import kotlinx.serialization.Serializable
import ui.navigation.routes.AddCredentialPreAuthnRoute
import ui.navigation.routes.AuthenticationViewRoute
import ui.navigation.routes.QrCodeScannerRoute
import ui.navigation.routes.Route
import ui.navigation.routes.SigningQtspSelectionRoute

class QrCodeScannerViewModel(
    savedStateHandle: SavedStateHandle,
    val walletMain: WalletMain,
) : ViewModel() {
    val mode = savedStateHandle.toRoute<QrCodeScannerRoute>().mode

    suspend fun startModeProcess(mode: QrCodeScannerMode, link: String) = when (mode) {
        QrCodeScannerMode.AUTHENTICATION -> prepareAuthentication(link)
        QrCodeScannerMode.SIGNING -> prepareSigning(link)
        QrCodeScannerMode.PROVISIONING -> prepareCredential(link)
    }

    fun onQrScanned(
        link: String,
        onSuccess: (Route) -> Unit,
        onFailure: (Throwable) -> Unit,
    ) = viewModelScope.launch {
        Napier.d("onQrScanned: $link")
        routeOrderForLink(mode, link).forEach {
            catchingUnwrapped {
                startModeProcess(it, link)
            }.onSuccess {
                onSuccess(it)
                return@launch
            }
        }
        onFailure(Throwable("Unable to parse: $link"))
    }

    private fun routeOrderForLink(mode: QrCodeScannerMode, link: String): List<QrCodeScannerMode> {
        val normalized = link.trim().lowercase()
        val preferredMode = when {
            normalized.startsWith("mdoc-openid4vp://") ||
                    normalized.startsWith("openid4vp://") ||
                    normalized.startsWith("eudi-openid4vp://") -> QrCodeScannerMode.AUTHENTICATION

            normalized.startsWith("openid-credential-offer://") ||
                    normalized.contains("credential_offer=") ||
                    normalized.contains("credential_offer_uri=") -> QrCodeScannerMode.PROVISIONING

            else -> mode
        }

        return listOf(preferredMode).plus(QrCodeScannerMode.entries.filter { it != preferredMode })
    }

    suspend fun prepareCredential(link: String) = catchingUnwrapped {
        AddCredentialPreAuthnRoute(walletMain.provisioningService.decodeCredentialOffer(link))
    }.onFailure {
        Napier.w("Error parsing credential offer", it)
    }.getOrThrow()


    suspend fun prepareAuthentication(link: String) = catchingUnwrapped {
        val buildAuthenticationConsentPageFromAuthenticationRequestUriUseCase =
            BuildAuthenticationConsentPageFromAuthenticationRequestUriUseCase(
                presentationService = walletMain.presentationService,
                httpService = walletMain.httpService,
            )
        val page =
            buildAuthenticationConsentPageFromAuthenticationRequestUriUseCase(link).getOrThrow()
        AuthenticationViewRoute(
            authenticationRequest = page.authenticationRequest,
            authorizationResponsePreparationState = page.authorizationResponsePreparationState,
            recipientLocation = page.recipientLocation,
            isCrossDeviceFlow = true
        )
    }.getOrThrow()


    suspend fun prepareSigning(link: String) = catchingUnwrapped {
        SigningQtspSelectionRoute(walletMain.signingService.parseSignatureRequestParameter(link))
    }.getOrThrow()
}

@Serializable
enum class QrCodeScannerMode() {
    SIGNING,
    AUTHENTICATION,
    PROVISIONING
}
