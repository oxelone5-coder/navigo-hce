import SwiftUI

struct ReaderView: View {
    @StateObject private var bridge = Bridge()

    final class Bridge: ObservableObject {
        @Published var lines: [String] = []
        @Published var active = false
        let reader = CardReader()
        init() {
            reader.onLine = { [weak self] in
                DispatchQueue.main.async { self?.lines.append($0) }
            }
            reader.onDone = { [weak self] in
                DispatchQueue.main.async { self?.active = false }
            }
        }
    }

    var body: some View {
        VStack(spacing: 12) {
            Button(bridge.active ? "Lecture en cours…" : "Lire la carte") {
                bridge.active = true
                bridge.reader.start()
            }
            .buttonStyle(.borderedProminent)
            .disabled(bridge.active)

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(bridge.lines.enumerated()), id: \.offset) { _, l in
                        Text(l).font(.system(.caption2, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
        }
        .padding(.top)
    }
}
