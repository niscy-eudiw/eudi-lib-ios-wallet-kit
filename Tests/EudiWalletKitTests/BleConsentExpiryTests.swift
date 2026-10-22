import Foundation
import Testing
import MdocDataTransfer18013
import MdocDataModel18013
import MdocSecurity18013
@testable import EudiWalletKit

struct BleConsentExpiryTests {
    @Test(arguments: [true, false])
    func consentAfterSessionCleanupReturnsErrorWithoutSending(_ accepted: Bool) async throws {
        let transport = ExpiredConsentTransport()
        let parameters = InitializeTransferData(dataFormats: [:], documentData: [:], documentKeyIndexes: [:],
            docMetadata: [:], docDisplayNames: [:], docKeyInfos: [:], trustValidator: ExpiredConsentTrust(),
            deviceAuthMethod: "deviceSignature", idsToDocTypes: [:], hashingAlgs: [:], bleTransferMode: .server)
        let service = try await BlePresentationService(parameters: parameters, authenticationContext: ThreadSafeAuthContext(),
            transportFactory: ExpiredConsentFactory(transport: transport))
        // This is the delegate state left by terminal transport cleanup while consent is open.
        service.status = .requestReceived
        service.sessionEncryption = nil
        service.deviceEngagement = nil
        service.deviceRequest = nil
        await #expect(throws: (any Error).self) {
            try await service.sendResponse(userAccepted: accepted, itemsToSend: [:],
                authenticationContext: ThreadSafeAuthContext(), onSuccess: nil)
        }
        #expect(transport.sends == 0)
        #expect(service.responsePreparationError != nil)
    }
}

private struct ExpiredConsentTrust: CertificateTrustValidator {
    var docType: String?
    func createCertTrustPath(chain: [Data]) async -> [Data]? { nil }
    func validateCertTrustPath(chain: [Data]) async -> (Bool, String?) { (false, nil) }
}

private struct ExpiredConsentFactory: BleTransportFactory {
    let transport: ExpiredConsentTransport
    #if !os(watchOS)
    func createServer() -> any MdocBleTransport { transport }
    #endif
    func createClient() -> any MdocBleTransport { transport }
}

private final class ExpiredConsentTransport: MdocBleTransport, @unchecked Sendable {
    required init() {}
    weak var delegate: (any MdocOfflineDelegate)?
    var sends = 0
    var isBlePoweredOn: Bool { true }
    var isAuthorized: Bool { true }
    var supportsL2cap: Bool { false }
    func startBleAdvertising() {}
    func stopBleAdvertising() {}
    func stop() {}
    func sendData(_ data: Data) { sends += 1 }
}
