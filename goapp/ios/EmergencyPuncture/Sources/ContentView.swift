import SwiftUI

struct ContentView: View {
    @State private var masterURL: String = "http://192.168.1.49:9122"
    @State private var remoteToken: String = ""
    @State private var killPassword: String = ""
    @State private var selectedProviderID: Int = 42
    @State private var providers: [ProviderLite] = []
    @State private var statusMessage: String = "Ready"
    @State private var statusTone: Color = .blue
    @State private var loading: Bool = false

    private let api = APIClient()

    var body: some View {
        NavigationStack {
            Form {
                Section("Master Connection") {
                    TextField("Master URL", text: $masterURL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                    SecureField("Remote Token (X-Puncture-Token)", text: $remoteToken)
                    Button("Load Providers") {
                        Task { await refreshProviders() }
                    }
                }

                Section("Emergency Puncture") {
                    Picker("Provider", selection: $selectedProviderID) {
                        ForEach(providers) { provider in
                            Text("ID \(provider.provider_id) - \(provider.name)").tag(provider.provider_id)
                        }
                    }
                    .pickerStyle(.menu)

                    SecureField("Kill Password (optional: append provider id)", text: $killPassword)

                    Button(role: .destructive) {
                        Task { await emergencyPuncture() }
                    } label: {
                        if loading {
                            ProgressView()
                        } else {
                            Text("Emergency Puncture Now")
                        }
                    }
                    .disabled(loading)
                }

                Section("Status") {
                    Text(statusMessage)
                        .foregroundStyle(statusTone)
                        .font(.system(.body, design: .monospaced))
                }
            }
            .navigationTitle("Emergency Puncture")
            .task {
                await refreshProviders()
            }
        }
    }

    private func resolvedProviderFromPassword() -> Int? {
        let digitsReversed = killPassword.reversed().prefix { $0.isNumber }
        guard !digitsReversed.isEmpty else {
            return nil
        }
        let digits = String(digitsReversed.reversed())
        guard let provider = Int(digits), (0...127).contains(provider) else {
            return nil
        }
        return provider
    }

    private func refreshProviders() async {
        loading = true
        defer { loading = false }
        do {
            let loaded = try await api.loadProviders(masterURL: masterURL, token: remoteToken)
            await MainActor.run {
                self.providers = loaded.sorted(by: { $0.provider_id < $1.provider_id })
                if let first = providers.first, !providers.contains(where: { $0.provider_id == selectedProviderID }) {
                    selectedProviderID = first.provider_id
                }
                statusMessage = "Loaded \(providers.count) provider(s)."
                statusTone = .green
            }
        } catch {
            await MainActor.run {
                statusMessage = "Load failed: \(error.localizedDescription)"
                statusTone = .red
            }
        }
    }

    private func emergencyPuncture() async {
        loading = true
        defer { loading = false }

        let providerID = resolvedProviderFromPassword() ?? selectedProviderID
        do {
            let response = try await api.punctureProvider(masterURL: masterURL, providerID: providerID, token: remoteToken)
            await MainActor.run {
                statusMessage = "Punctured provider \(response.provider_id ?? providerID)."
                statusTone = .orange
            }
            await refreshProviders()
        } catch {
            await MainActor.run {
                statusMessage = "Emergency puncture failed: \(error.localizedDescription)"
                statusTone = .red
            }
        }
    }
}
