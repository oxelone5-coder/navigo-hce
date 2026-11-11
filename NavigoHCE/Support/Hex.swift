import Foundation

extension Data {
    var hex: String { map { String(format: "%02X ", $0) }.joined() }
}

func decodeAPDU(_ d: Data) -> String {
    guard d.count >= 4 else { return "court" }
    let cla = d[0], ins = d[1]
    var s = String(format: "CLA=%02X INS=%02X ", cla, ins)
    switch (cla, ins) {
    case (0x00, 0xA4): s += "SELECT"
    case (0x00, 0xB2): s += "READ RECORD"
    case (0x8A, 0x30): s += "OPEN SECURE SESSION"
    case (_, 0xCA):    s += "GET DATA"
    default:           s += "?"
    }
    return s + " | " + d.hex
}
