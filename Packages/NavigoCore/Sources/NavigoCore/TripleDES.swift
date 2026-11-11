import Foundation

/// Protocole d'abstraction pour la crypto Calypso (3DES-CBC-MAC).
/// L'implémentation iOS utilisera CommonCrypto ; ici, Swift pur.
public protocol CalypsoCrypto {
    /// 3DES-CBC-MAC ISO 9797-1 algorithme 3 sur `data` avec la clé Calypso 16 octets
    /// (K1‖K2‖K1). Retourne le MAC sur 8 octets.
    func tripleDesCbcMac(key: Data, data: Data) -> Data
    /// Chiffrement 3DES-ECB d'un bloc de 8 octets.
    func tripleDesEcbEncrypt(key: Data, block: Data) -> Data
    /// Déchiffrement 3DES-ECB d'un bloc de 8 octets.
    func tripleDesEcbDecrypt(key: Data, block: Data) -> Data
}

/// Implémentation 3DES en Swift pur (aucune dépendance Apple).
/// Conforme à TDEA (FIPS 46-3) : E_K1(D_K2(E_K3(block))).
/// Clé acceptée : 16 octets (K1‖K2, K3 déduit = K1) ou 24 octets (K1‖K2‖K3).
public final class PureSwiftTripleDES: CalypsoCrypto {

    // MARK: - Tables DES (FIPS 46-3)

    private static let ip: [UInt8] = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ]

    private static let fp: [UInt8] = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ]

    private static let e: [UInt8] = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]

    private static let p: [UInt8] = [
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    ]

    private static let sBoxes: [[[UInt8]]] = [
        [ // S1
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        [ // S2
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        [ // S3
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 1, 15, 11],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        [ // S4
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        [ // S5
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        [ // S6
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        [ // S7
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        [ // S8
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]

    private static let pc1: [UInt8] = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ]

    private static let pc2: [UInt8] = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ]

    private static let shifts: [Int] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    // MARK: - Validation de clé (testable, ne tue pas le processus)

    public static func isValidKey(_ key: Data) -> Bool {
        key.count == 16 || key.count == 24
    }

    /// Décompose la clé Calypso en K1, K2, K3.
    /// - 16 octets : K1‖K2, K3 déduit = K1 (TDEA deux clés).
    /// - 24 octets : K1‖K2‖K3 (TDEA trois clés).
    private func preparedKeys(key: Data) -> (k1: Data, k2: Data, k3: Data) {
        precondition(Self.isValidKey(key),
                     "Clé Calypso : 16 octets (K1‖K2) ou 24 octets (K1‖K2‖K3)")
        let k1 = key.subdata(in: 0..<8)
        let k2 = key.subdata(in: 8..<16)
        let k3: Data
        if key.count == 16 {
            k3 = k1
        } else {
            k3 = key.subdata(in: 16..<24)
        }
        return (k1, k2, k3)
    }

    // MARK: - DES bas niveau

    /// Génère les 16 sous-clés de 48 bits à partir d'une clé 64 bits (8 octets, parité ignorée).
    private static func generateSubkeys(key: Data) -> [[UInt8]] {
        var keyBits = bitArray(from: key, count: 64)
        var pc1bits: [UInt8] = []
        for i in 0..<56 { pc1bits.append(keyBits[Int(pc1[i]) - 1]) }

        var c = Array(pc1bits[0..<28])
        var d = Array(pc1bits[28..<56])

        var subkeys: [[UInt8]] = []
        for round in 0..<16 {
            let s = shifts[round]
            c = Array(c[s...]) + Array(c[0..<s])
            d = Array(d[s...]) + Array(d[0..<s])
            var cd = c + d
            var subkey: [UInt8] = []
            for i in 0..<48 { subkey.append(cd[Int(pc2[i]) - 1]) }
            subkeys.append(subkey)
        }
        return subkeys
    }

    /// Fonction de round DES (F).
    private static func desF(right: [UInt8], subkey: [UInt8]) -> [UInt8] {
        var expanded: [UInt8] = []
        for i in 0..<48 { expanded.append(right[Int(e[i]) - 1]) }

        for i in 0..<48 { expanded[i] ^= subkey[i] }

        var sboxOut: [UInt8] = []
        for box in 0..<8 {
            let offset = box * 6
            let row = ((expanded[offset] << 1) & 0x02) | (expanded[offset + 5] & 0x01)
            let col = (expanded[offset + 1] << 3) | (expanded[offset + 2] << 2) |
                      (expanded[offset + 3] << 1) | (expanded[offset + 4])
            let val = sBoxes[box][Int(row)][Int(col)]
            sboxOut.append((val >> 3) & 1)
            sboxOut.append((val >> 2) & 1)
            sboxOut.append((val >> 1) & 1)
            sboxOut.append(val & 1)
        }

        var result: [UInt8] = []
        for i in 0..<32 { result.append(sboxOut[Int(p[i]) - 1]) }
        return result
    }

    /// Chiffre/déchiffre un bloc de 64 bits avec DES.
    private static func desBlock(block: [UInt8], subkeys: [[UInt8]], encrypt: Bool) -> Data {
        var bits = bitArray(from: Data(block), count: 64)

        var permuted: [UInt8] = []
        for i in 0..<64 { permuted.append(bits[Int(ip[i]) - 1]) }

        var left = Array(permuted[0..<32])
        var right = Array(permuted[32..<64])

        let roundIndices = encrypt ? Array(0..<16) : Array((0..<16).reversed())
        for round in roundIndices {
            let f = desF(right: right, subkey: subkeys[round])
            var newRight: [UInt8] = []
            for i in 0..<32 { newRight.append(left[i] ^ f[i]) }
            left = right
            right = newRight
        }

        var preFp = right + left
        var resultBits: [UInt8] = []
        for i in 0..<64 { resultBits.append(preFp[Int(fp[i]) - 1]) }
        return PureSwiftTripleDES.bitsToData(resultBits)
    }

    /// Convertit des données en tableau de bits (MSB first), tronqué ou complété à `count`.
    private static func bitArray(from data: Data, count: Int) -> [UInt8] {
        var bits: [UInt8] = []
        for byte in data {
            for i in (0..<8).reversed() {
                bits.append((byte >> i) & 1)
            }
        }
        if bits.count > count { bits = Array(bits[0..<count]) }
        while bits.count < count { bits.append(0) }
        return bits
    }

    /// Convertit un tableau de bits en données (groupes de 8 bits).
    private static func bitsToData(_ bits: [UInt8]) -> Data {
        var result = Data()
        for i in stride(from: 0, to: bits.count, by: 8) {
            var byte: UInt8 = 0
            for j in 0..<8 where i + j < bits.count {
                byte = (byte << 1) | bits[i + j]
            }
            result.append(byte)
        }
        return result
    }

    // MARK: - Bourrage ISO 9797-1 méthode 2

    /// Bourrage méthode 2 : ajoute 0x80 puis des 0x00 jusqu'à l'alignement sur 8 octets.
    /// Toujours appliqué, même si `data` est déjà aligné (ajoute un bloc complet).
    private static func padMethod2(_ data: Data) -> Data {
        var padded = data
        padded.append(0x80)
        while padded.count % 8 != 0 {
            padded.append(0x00)
        }
        return padded
    }

    // MARK: - CalypsoCrypto

    public func tripleDesEcbEncrypt(key: Data, block: Data) -> Data {
        let (k1, k2, k3) = preparedKeys(key: key)
        precondition(block.count == 8, "bloc doit faire 8 octets")

        let sk1 = PureSwiftTripleDES.generateSubkeys(key: k1)
        let sk2 = PureSwiftTripleDES.generateSubkeys(key: k2)
        let sk3 = PureSwiftTripleDES.generateSubkeys(key: k3)

        let e1 = PureSwiftTripleDES.desBlock(block: [UInt8](block), subkeys: sk1, encrypt: true)
        let d2 = PureSwiftTripleDES.desBlock(block: [UInt8](e1), subkeys: sk2, encrypt: false)
        let e3 = PureSwiftTripleDES.desBlock(block: [UInt8](d2), subkeys: sk3, encrypt: true)

        return e3
    }

    public func tripleDesEcbDecrypt(key: Data, block: Data) -> Data {
        let (k1, k2, k3) = preparedKeys(key: key)
        precondition(block.count == 8, "bloc doit faire 8 octets")

        let sk1 = PureSwiftTripleDES.generateSubkeys(key: k1)
        let sk2 = PureSwiftTripleDES.generateSubkeys(key: k2)
        let sk3 = PureSwiftTripleDES.generateSubkeys(key: k3)

        // TDEA decrypt : D_K3(E_K2(D_K1(ct)))
        let d3 = PureSwiftTripleDES.desBlock(block: [UInt8](block), subkeys: sk3, encrypt: false)
        let e2 = PureSwiftTripleDES.desBlock(block: [UInt8](d3), subkeys: sk2, encrypt: true)
        let d1 = PureSwiftTripleDES.desBlock(block: [UInt8](e2), subkeys: sk1, encrypt: false)

        return d1
    }

    public func tripleDesCbcMac(key: Data, data: Data) -> Data {
        let (k1, k2, _) = preparedKeys(key: key)

        // ISO 9797-1 MAC algorithme 3, bourrage méthode 2, IV nul.
        // Chaîne CBC avec K1 sur tous les blocs, puis D_K2 sur le dernier bloc MAC,
        // puis E_K1 pour le résultat final.
        let padded = PureSwiftTripleDES.padMethod2(data)

        let sk1 = PureSwiftTripleDES.generateSubkeys(key: k1)
        let sk2 = PureSwiftTripleDES.generateSubkeys(key: k2)

        var iv: [UInt8] = Array(repeating: 0, count: 8)
        var mac: [UInt8] = Array(repeating: 0, count: 8)

        for i in stride(from: 0, to: padded.count, by: 8) {
            let block = padded.subdata(in: i..<i + 8)
            var xored: [UInt8] = []
            for j in 0..<8 { xored.append(block[j] ^ iv[j]) }
            let encrypted = PureSwiftTripleDES.desBlock(block: xored, subkeys: sk1, encrypt: true)
            iv = [UInt8](encrypted)
            mac = [UInt8](encrypted)
        }

        let decrypted = PureSwiftTripleDES.desBlock(block: mac, subkeys: sk2, encrypt: false)
        let final = PureSwiftTripleDES.desBlock(block: [UInt8](decrypted), subkeys: sk1, encrypt: true)

        return final
    }
}
