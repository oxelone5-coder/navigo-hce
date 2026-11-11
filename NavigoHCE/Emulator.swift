import Foundation
import CoreNFC
import UIKit

@MainActor
final class Emulator: ObservableObject {
    @Published var log: [String] = []
    @Published var running = false
    private var session: CardSession?
    private var intent: NFCPresentmentIntentAssertion?

    func start() {
        Task {
            guard NFCReaderSession.readingAvailable,
                  CardSession.isSupported,
                  await CardSession.isEligible else {
                log.append("HCE indisponible : entitlement, région ou iOS")
                return
            }
            do {
                intent = try await NFCPresentmentIntentAssertion.acquire()
                let s = try await CardSession()
                session = s
                s.alertMessage = "Approche l'iPhone du lecteur"
                running = true
                UIApplication.shared.isIdleTimerDisabled = true

                for try await event in s.eventStream {
                    switch event {
                    case .sessionStarted:
                        log.append("session ouverte")
                        if await !s.isEmulationInProgress {
                            try await s.startEmulation()
                        }
                    case .readerDetected:
                        log.append("=== LECTEUR DÉTECTÉ ===")
                        if await !s.isEmulationInProgress {
                            try await s.startEmulation()
                        }
                    case .readerDeselected:
                        log.append("lecteur retiré")
                    case .received(let apdu):
                        log.append(decodeAPDU(apdu.payload))
                        try await apdu.respond(response: Data([0x90, 0x00]))
                    case .sessionInvalidated(let reason):
                        log.append("session invalidée (\(reason))")
                        stop()
                    @unknown default:
                        break
                    }
                }
            } catch {
                log.append("erreur : \(error.localizedDescription)")
                stop()
            }
        }
    }

    func stop() {
        running = false
        UIApplication.shared.isIdleTimerDisabled = false
        session = nil
        intent = nil
    }
}
