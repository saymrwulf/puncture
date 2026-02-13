import Foundation

struct ProviderLite: Decodable, Identifiable, Hashable {
    let provider_id: Int
    let name: String
    var id: Int { provider_id }
}

struct LiveStatePayload: Decodable {
    let ok: Bool?
    let state: LiveState?
    let providers: [ProviderLite]?
}

struct LiveState: Decodable {
    let providers: [ProviderLite]
}

struct RemotePunctureRequest: Encodable {
    let provider_id: Int
}

struct RemotePunctureResponse: Decodable {
    let ok: Bool
    let error: String?
    let provider_id: Int?
}
