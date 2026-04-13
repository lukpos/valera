package domain

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dcapi.request.DCAPIWalletRequest
import at.asitplus.wallet.app.common.HttpService
import at.asitplus.wallet.app.common.PresentationService
import at.asitplus.wallet.app.common.domain.requestcertificates.RequestCertificateValidator
import io.github.aakira.napier.Napier
import ui.navigation.routes.AuthenticationViewRoute

class BuildAuthenticationConsentPageFromAuthenticationRequest(
    val presentationService: PresentationService,
    httpService: HttpService,
) {
    private val tag = "RequestCert.BuildConsent"
    private val requestCertificateValidator = RequestCertificateValidator(httpService)

    suspend operator fun invoke(
        request: DCAPIWalletRequest.OpenId4Vp,
    ): KmmResult<AuthenticationViewRoute> = catching {
        Napier.d("Preparing authentication consent page from DC API request.", tag = tag)
        val preparationState = presentationService.startAuthorizationResponsePreparation(request)
            .onFailure { Napier.e("Authorization response preparation failed.", it, tag = tag) }
            .getOrThrow()
        val validationResult = requestCertificateValidator.validate(preparationState)
        val recipientDisplay = validationResult.preferredRecipientDisplay()
            ?: preparationState.request.parameters.clientId
            ?: ""
        Napier.d(
            "Consent page prepared. registrationCertPayloads=${validationResult.registrationCertPayloads.size}, " +
                "recipientDisplay='$recipientDisplay'",
            tag = tag
        )

        AuthenticationViewRoute(
            authenticationRequest = preparationState.request,
            authorizationResponsePreparationState = preparationState,
            recipientLocation = recipientDisplay,
            isCrossDeviceFlow = false,
        )
    }
}
