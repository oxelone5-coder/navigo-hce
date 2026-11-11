import SwiftUI

struct ContentView: View {
    @StateObject private var emu = Emulator()

    var body: some View {
        VStack(spacing: 12) {
            Text(emu.running ? "ÉMULATION ACTIVE" : "Prêt")
                .font(.headline)
                .foregroundStyle(emu.running ? .green : .primary)

            Button(emu.running ? "Arrêter" : "Démarrer") {
                emu.running ? emu.stop() : emu.start()
            }
            .buttonStyle(.borderedProminent)

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(emu.log.enumerated()), id: \.offset) { _, l in
                        Text(l).font(.system(.caption2, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
        }
        .padding(.top)
    }
}
