import Foundation
import CoreNFC

final class CardReader: NSObject, NFCTagReaderSessionDelegate {
    var onLine: ((String) -> Void)?
    var onDone: (() -> Void)?
    private var session: NFCTagReaderSession?
    private var dumpURL: URL?

    static let aid: [UInt8] = [
        0xA0,0x00,0x00,0x05,0x59,0x10,0x10,0xFF,
        0xFF,0xFF,0xFF,0x89,0x00,0x00,0x01,0x00
    ]

    func start() {
        guard NFCTagReaderSession.readingAvailable else {
            onLine?("lecteur NFC indisponible"); return
        }
        let dir = FileManager.default.urls(for: .documentDirectory,
                                           in: .userDomainMask)[0]
                   .appendingPathComponent("dumps", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir,
                                                 withIntermediateDirectories: true)
        let f = dir.appendingPathComponent(
            "carte-\(ISO8601DateFormatter().string(from: Date())).txt")
        FileManager.default.createFile(atPath: f.path, contents: nil)
        dumpURL = f

        session = NFCTagReaderSession(pollingOption: .iso14443,
                                      delegate: self, queue: nil)
        session?.alertMessage = "Approche la carte"
        session?.begin()
    }

    private func write(_ s: String) {
        onLine?(s)
        guard let u = dumpURL,
              let h = try? FileHandle(forWritingTo: u) else { return }
        defer { try? h.close() }
        try? h.seekToEnd()
        try? h.write(contentsOf: Data((s + "\n").utf8))
    }

    func tagReaderSessionDidBecomeActive(_ s: NFCTagReaderSession) {}

    func tagReaderSession(_ s: NFCTagReaderSession,
                          didInvalidateWithError e: Error) {
        write("session close : \(e.localizedDescription)")
        session = nil
        onDone?()
    }

    func tagReaderSession(_ s: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let tag = tags.first else { s.restartPolling(); return }
        s.connect(to: tag) { err in
            guard err == nil, case let .iso7816(t) = tag else {
                s.restartPolling(); return
            }
            self.run(t, s)
        }
    }

    /// Envoie une APDU en absorbant 6Cxx (Le corrigé) et 61xx (GET RESPONSE).
    private func send(_ tag: NFCISO7816Tag, _ s: NFCTagReaderSession,
                      cla: UInt8, ins: UInt8, p1: UInt8, p2: UInt8,
                      data: Data, le: Int,
                      done: @escaping (Data, UInt8, UInt8) -> Void) {
        let apdu = NFCISO7816APDU(instructionClass: cla, instructionCode: ins,
                                  p1Parameter: p1, p2Parameter: p2,
                                  data: data, expectedResponseLength: le)
        tag.sendCommand(apdu: apdu) { d, sw1, sw2, _ in
            if sw1 == 0x6C {
                self.send(tag, s, cla: cla, ins: ins, p1: p1, p2: p2,
                          data: data, le: Int(sw2), done: done)
            } else if sw1 == 0x61 {
                let gr = NFCISO7816APDU(instructionClass: 0x00,
                                        instructionCode: 0xC0,
                                        p1Parameter: 0x00, p2Parameter: 0x00,
                                        data: Data(),
                                        expectedResponseLength: Int(sw2))
                tag.sendCommand(apdu: gr) { d2, s1, s2, _ in
                    done(d + d2, s1, s2)
                }
            } else {
                done(d, sw1, sw2)
            }
        }
    }

    private func run(_ tag: NFCISO7816Tag, _ s: NFCTagReaderSession) {
        write("UID " + tag.identifier.hex)
        write("HIST " + (tag.historicalBytes?.hex ?? "-"))
        write("ATR " + (tag.historicalBytes != nil ? "present" : "absent"))

        send(tag, s, cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00,
             data: Data(CardReader.aid), le: 256) { _, sw1, sw2 in
            self.write(String(format: "SELECT AID → %02X%02X", sw1, sw2))
            if sw1 == 0x90 || sw1 == 0x61 {
                self.sweep(tag, s, sfi: 1)
            } else {
                self.write("AID refusé — lecture directe sans SELECT")
                self.sweep(tag, s, sfi: 1)
            }
        }
    }

    // P2 = (SFI << 3) | 0b100 : lecture de l'enregistrement P1 du fichier SFI.
    private func sweep(_ tag: NFCISO7816Tag, _ s: NFCTagReaderSession, sfi: Int) {
        guard sfi <= 30 else {
            write("=== fin du balayage ===")
            s.alertMessage = "Dump terminé"
            s.invalidate()
            return
        }
        read(tag, s, sfi: sfi, rec: 1)
    }

    private func read(_ tag: NFCISO7816Tag, _ s: NFCTagReaderSession,
                      sfi: Int, rec: UInt8) {
        let p2 = UInt8((sfi << 3) | 0x04)
        send(tag, s, cla: 0x00, ins: 0xB2, p1: rec, p2: p2,
             data: Data(), le: 256) { d, sw1, sw2 in
            switch sw1 {
            case 0x90:
                self.write(String(format: "SFI %02X R%d → %@", sfi, rec, d.hex))
            case 0x6A where sw2 == 0x83:
                self.sweep(tag, s, sfi: sfi + 1); return
            case 0x69 where sw2 == 0x82:
                self.write(String(format: "SFI %02X R%d → 6982 (protégé)", sfi, rec))
            case 0x6A:
                self.sweep(tag, s, sfi: sfi + 1); return
            default:
                self.write(String(format: "SFI %02X R%d SW %02X%02X",
                                  sfi, rec, sw1, sw2))
            }
            if rec < 4 { self.read(tag, s, sfi: sfi, rec: rec + 1) }
            else { self.sweep(tag, s, sfi: sfi + 1) }
        }
    }
}
