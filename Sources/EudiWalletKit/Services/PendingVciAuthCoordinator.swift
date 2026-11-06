/*
Copyright (c) 2026 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import Foundation
import Logging

/// Owns the browser authorization shared by issuer services, including the temporary
/// child services created for offer-based issuance. All session access is UI-bound.
@MainActor
final class PendingVciAuthCoordinator {
    static let shared = PendingVciAuthCoordinator()

    private struct Pending {
        let id: UUID
        let continuation: CheckedContinuation<AsWebOutcome, Error>
        let redirectURI: URL
        let presentationSchemes: [String]
        let cancel: () -> Void

        func isAuthorizationRedirect(_ url: URL) -> Bool {
            url.scheme?.lowercased() == redirectURI.scheme?.lowercased()
                && url.host?.lowercased() == redirectURI.host?.lowercased()
                && url.port == redirectURI.port && url.path == redirectURI.path
        }

        func isPresentationRedirect(_ url: URL) -> Bool {
            presentationSchemes.contains { $0.lowercased() == url.scheme?.lowercased() }
        }
    }

    private var pending: Pending?
    private let logger = Logger(label: "OpenId4VCI.PendingAuth")

    func start(id: UUID, continuation: CheckedContinuation<AsWebOutcome, Error>, redirectURI: URL,
               presentationSchemes: [String], cancel: @escaping () -> Void) throws {
        guard pending == nil else {
            throw WalletError(description: "Another VCI authorization session is already active", code: .authorizationFailed)
        }
        pending = Pending(id: id, continuation: continuation, redirectURI: redirectURI,
                          presentationSchemes: presentationSchemes, cancel: cancel)
    }

    /// Only the matching browser session may drain the continuation. In particular,
    /// cancellation callbacks from an externally resumed session cannot drain its successor.
    func complete(id: UUID, url: URL?, error: (any Error)?) {
        guard let current = take(id: id) else { return }
        if let error {
            current.continuation.resume(throwing: WalletError.authRequestFailed(error: error))
        } else if let url {
            resolve(current, url: url)
        } else {
            current.continuation.resume(throwing: WalletError(description: "Authorization response does not include a url", code: .authorizationFailed))
        }
    }

    @discardableResult
    func resume(with url: URL) -> Bool {
        guard let current = pending,
              current.isAuthorizationRedirect(url) || current.isPresentationRedirect(url) else { return false }
        // Clear ownership before cancel(), which can itself deliver a browser callback.
        pending = nil
        current.cancel()
        resolve(current, url: url)
        return true
    }

    func cancel(id: UUID) {
        guard let current = take(id: id) else { return }
        current.cancel()
        current.continuation.resume(throwing: CancellationError())
    }

    private func take(id: UUID) -> Pending? {
        guard let current = pending, current.id == id else { return nil }
        pending = nil
        return current
    }

    private func resolve(_ current: Pending, url: URL) {
        // The OAuth callback may use a registered app scheme too; match it first.
        if current.isAuthorizationRedirect(url) {
            let query = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems
            guard let code = query?.first(where: { $0.name == "code" })?.value else {
                current.continuation.resume(throwing: WalletError(description: "Authorization response does not include a code", code: .authorizationFailed))
                return
            }
            logger.info("Authorization code: \(code)")
            let state = query?.first(where: { $0.name == "state" })?.value
            let iss = query?.first(where: { $0.name == "iss" })?.value
            current.continuation.resume(returning: .code(code, state: state, iss: iss))
        } else if current.isPresentationRedirect(url) {
            logger.info("Dynamic issuance url: \(url)")
            current.continuation.resume(returning: .presentation_request(url))
        } else {
            current.continuation.resume(throwing: WalletError(description: "Authorization response does not match the configured redirect URI", code: .authorizationFailed))
        }
    }
}
