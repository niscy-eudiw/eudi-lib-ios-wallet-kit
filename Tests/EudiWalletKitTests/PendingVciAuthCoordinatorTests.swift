import Foundation
import Testing
@testable import EudiWalletKit

@MainActor
struct PendingVciAuthCoordinatorTests {
    private let redirectURI = URL(string: "wallet://authorize/callback")!

    @Test func externalRedirectResumesOnceAndPreservesResponseParameters() async throws {
        let coordinator = PendingVciAuthCoordinator()
        let id = UUID()
        var cancellations = 0
        let outcome: AsWebOutcome = try await withCheckedThrowingContinuation { continuation in
            try! coordinator.start(id: id, continuation: continuation, redirectURI: redirectURI,
                                   presentationSchemes: ["wallet"], cancel: { cancellations += 1 })
            let url = URL(string: "wallet://authorize/callback?code=fineid-code&state=expected&iss=https%3A%2F%2Fissuer.example")!
            #expect(coordinator.resume(with: url))
            #expect(!coordinator.resume(with: url))
            coordinator.complete(id: id, url: nil, error: URLError(.cancelled))
        }
        guard case let .code(code, state, iss) = outcome else {
            Issue.record("OAuth callback must not be classified as a presentation request")
            return
        }
        #expect(code == "fineid-code")
        #expect(state == "expected")
        #expect(iss == "https://issuer.example")
        #expect(cancellations == 1)
    }

    @Test func unrelatedRedirectDoesNotConsumePendingAuthorization() async throws {
        let coordinator = PendingVciAuthCoordinator()
        let id = UUID()
        let outcome: AsWebOutcome = try await withCheckedThrowingContinuation { continuation in
            try! coordinator.start(id: id, continuation: continuation, redirectURI: redirectURI,
                                   presentationSchemes: [], cancel: {})
            #expect(!coordinator.resume(with: URL(string: "other://authorize/callback?code=wrong")!))
            #expect(!coordinator.resume(with: URL(string: "wallet://authorize/other?code=wrong")!))
            #expect(!coordinator.resume(with: URL(string: "wallet://other/callback?code=wrong")!))
            #expect(coordinator.resume(with: URL(string: "wallet://authorize/callback?code=correct&state=state")!))
        }
        guard case let .code(code, state, _) = outcome else {
            Issue.record("Expected authorization code")
            return
        }
        #expect(code == "correct")
        #expect(state == "state")
    }

    @Test func browserRedirectSupportsDynamicIssuance() async throws {
        let coordinator = PendingVciAuthCoordinator()
        let id = UUID()
        let url = URL(string: "openid4vp://present?request_uri=https://issuer.example/request")!
        let outcome: AsWebOutcome = try await withCheckedThrowingContinuation { continuation in
            try! coordinator.start(id: id, continuation: continuation, redirectURI: redirectURI,
                                   presentationSchemes: ["openid4vp"], cancel: { Issue.record("Browser completion must not cancel") })
            coordinator.complete(id: id, url: url, error: nil)
        }
        guard case let .presentation_request(receivedURL) = outcome else {
            Issue.record("Expected presentation request")
            return
        }
        #expect(receivedURL == url)
        #expect(!coordinator.resume(with: redirectURI))
    }

    @Test func cancellationDrainsSessionAndIgnoresLateCallback() async {
        let coordinator = PendingVciAuthCoordinator()
        let id = UUID()
        var cancellations = 0
        await #expect(throws: CancellationError.self) {
            let _: AsWebOutcome = try await withCheckedThrowingContinuation { continuation in
                try! coordinator.start(id: id, continuation: continuation, redirectURI: redirectURI,
                                       presentationSchemes: [], cancel: { cancellations += 1 })
                coordinator.cancel(id: id)
                coordinator.complete(id: id, url: redirectURI, error: nil)
            }
        }
        #expect(cancellations == 1)
        #expect(!coordinator.resume(with: redirectURI))
    }

    @Test func oldBrowserCallbackCannotCompleteNewSession() async throws {
        let coordinator = PendingVciAuthCoordinator()
        let oldID = UUID()
        let _: AsWebOutcome = try await withCheckedThrowingContinuation { continuation in
            try! coordinator.start(id: oldID, continuation: continuation, redirectURI: redirectURI,
                                   presentationSchemes: [], cancel: {})
            #expect(coordinator.resume(with: URL(string: "wallet://authorize/callback?code=old")!))
        }
        let newID = UUID()
        let outcome: AsWebOutcome = try await withCheckedThrowingContinuation { continuation in
            try! coordinator.start(id: newID, continuation: continuation, redirectURI: redirectURI,
                                   presentationSchemes: [], cancel: {})
            coordinator.complete(id: oldID, url: nil, error: URLError(.cancelled))
            #expect(coordinator.resume(with: URL(string: "wallet://authorize/callback?code=new")!))
        }
        guard case let .code(code, _, _) = outcome else {
            Issue.record("Expected new session's authorization code")
            return
        }
        #expect(code == "new")
    }

    @Test func malformedCallbackFailsAndReleasesSession() async {
        let coordinator = PendingVciAuthCoordinator()
        await #expect(throws: WalletError.self) {
            let _: AsWebOutcome = try await withCheckedThrowingContinuation { continuation in
                try! coordinator.start(id: UUID(), continuation: continuation, redirectURI: redirectURI,
                                       presentationSchemes: ["wallet"], cancel: {})
                #expect(coordinator.resume(with: redirectURI))
            }
        }
        #expect(!coordinator.resume(with: redirectURI))
    }

    @Test func overlappingAuthorizationIsRejectedWithoutReplacingOriginal() async throws {
        let coordinator = PendingVciAuthCoordinator()
        let outcome: AsWebOutcome = try await withCheckedThrowingContinuation { continuation in
            try! coordinator.start(id: UUID(), continuation: continuation, redirectURI: redirectURI,
                                   presentationSchemes: [], cancel: {})
            #expect(throws: WalletError.self) {
                try coordinator.start(id: UUID(), continuation: continuation, redirectURI: redirectURI,
                                      presentationSchemes: [], cancel: {})
            }
            #expect(coordinator.resume(with: URL(string: "wallet://authorize/callback?code=original")!))
        }
        guard case let .code(code, _, _) = outcome else {
            Issue.record("Expected original authorization")
            return
        }
        #expect(code == "original")
    }

    @Test func browserErrorsAndMissingURLReleasePendingSession() async {
        let coordinator = PendingVciAuthCoordinator()
        for error: (any Error)? in [URLError(.cancelled), nil] {
            let id = UUID()
            await #expect(throws: WalletError.self) {
                let _: AsWebOutcome = try await withCheckedThrowingContinuation { continuation in
                    try! coordinator.start(id: id, continuation: continuation, redirectURI: redirectURI,
                                           presentationSchemes: [], cancel: {})
                    coordinator.complete(id: id, url: nil, error: error)
                }
            }
            #expect(!coordinator.resume(with: redirectURI))
        }
    }

    @Test func externalPresentationRedirectClosesBrowser() async throws {
        let coordinator = PendingVciAuthCoordinator()
        var cancellations = 0
        let url = URL(string: "openid4vp://present?request_uri=https://issuer.example/request")!
        let outcome: AsWebOutcome = try await withCheckedThrowingContinuation { continuation in
            try! coordinator.start(id: UUID(), continuation: continuation, redirectURI: redirectURI,
                                   presentationSchemes: ["openid4vp"], cancel: { cancellations += 1 })
            #expect(coordinator.resume(with: url))
        }
        guard case let .presentation_request(receivedURL) = outcome else {
            Issue.record("Expected external presentation request")
            return
        }
        #expect(receivedURL == url)
        #expect(cancellations == 1)
    }
}
