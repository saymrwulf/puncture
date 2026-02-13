import Foundation

enum APIError: Error, LocalizedError {
    case invalidURL
    case badStatus(Int)
    case backend(String)

    var errorDescription: String? {
        switch self {
        case .invalidURL: return "Invalid URL"
        case .badStatus(let code): return "HTTP \(code)"
        case .backend(let message): return message
        }
    }
}

@MainActor
final class APIClient {
    func loadProviders(masterURL: String, token: String) async throws -> [ProviderLite] {
        guard let url = URL(string: masterURL.trimmingCharacters(in: .whitespacesAndNewlines) + "/api/live/state") else {
            throw APIError.invalidURL
        }
        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        if !token.isEmpty {
            req.addValue(token, forHTTPHeaderField: "X-Puncture-Token")
        }
        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse else { throw APIError.badStatus(-1) }
        guard (200...299).contains(http.statusCode) else { throw APIError.badStatus(http.statusCode) }

        if let top = try? JSONDecoder().decode([String: [ProviderLite]].self, from: data), let providers = top["providers"] {
            return providers
        }
        if let payload = try? JSONDecoder().decode(LiveStatePayload.self, from: data) {
            if let providers = payload.providers {
                return providers
            }
            if let state = payload.state {
                return state.providers
            }
        }
        return []
    }

    func punctureProvider(masterURL: String, providerID: Int, token: String) async throws -> RemotePunctureResponse {
        guard let url = URL(string: masterURL.trimmingCharacters(in: .whitespacesAndNewlines) + "/api/remote/puncture-provider") else {
            throw APIError.invalidURL
        }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.addValue("application/json", forHTTPHeaderField: "Content-Type")
        if !token.isEmpty {
            req.addValue(token, forHTTPHeaderField: "X-Puncture-Token")
        }

        req.httpBody = try JSONEncoder().encode(RemotePunctureRequest(provider_id: providerID))
        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse else { throw APIError.badStatus(-1) }

        let decoded = (try? JSONDecoder().decode(RemotePunctureResponse.self, from: data)) ?? RemotePunctureResponse(ok: false, error: "Invalid response", provider_id: nil)
        guard (200...299).contains(http.statusCode) else {
            throw APIError.backend(decoded.error ?? "HTTP \(http.statusCode)")
        }
        if !decoded.ok {
            throw APIError.backend(decoded.error ?? "Puncture rejected")
        }
        return decoded
    }
}
