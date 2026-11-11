import XCTest
@testable import NavigoCore

final class NavigoCoreTests: XCTestCase {

    // MARK: - Hex / decodeAPDU

    func testDataHex() {
        let data: Data = Data([0x00, 0xA4, 0x04, 0x00])
        XCTAssertEqual(data.hex, "00 A4 04 00 ")
    }

    func testDecodeAPDUSelect() {
        let apdu: Data = Data([0x00, 0xA4, 0x04, 0x00]) + Data(calypsoAID)
        let decoded = decodeAPDU(apdu)
        XCTAssertTrue(decoded.contains("SELECT"))
        XCTAssertTrue(decoded.contains("CLA=00 INS=A4"))
    }

    func testDecodeAPDUReadRecord() {
        let apdu: Data = Data([0x00, 0xB2, 0x01, 0x04])
        let decoded = decodeAPDU(apdu)
        XCTAssertTrue(decoded.contains("READ RECORD"))
    }

    func testDecodeAPDUOpenSecureSession() {
        let apdu: Data = Data([0x8A, 0x30, 0x00, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        let decoded = decodeAPDU(apdu)
        XCTAssertTrue(decoded.contains("OPEN SECURE SESSION"))
    }

    func testDecodeAPDUGetData() {
        let apdu: Data = Data([0x00, 0xCA, 0x00, 0x00])
        let decoded = decodeAPDU(apdu)
        XCTAssertTrue(decoded.contains("GET DATA"))
    }

    func testDecodeAPDUUnknown() {
        let apdu: Data = Data([0x00, 0xFF, 0x00, 0x00])
        let decoded = decodeAPDU(apdu)
        XCTAssertTrue(decoded.contains("?"))
    }

    func testDecodeAPDUTooShort() {
        let apdu: Data = Data([0x00, 0xA4])
        let decoded = decodeAPDU(apdu)
        XCTAssertEqual(decoded, "court")
    }

    // MARK: - TripleDES : validation de clé (ne tue pas le processus)

    func testIsValidKey() {
        XCTAssertTrue(PureSwiftTripleDES.isValidKey(
            Data([0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
                  0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0x01]))) // 16
        XCTAssertTrue(PureSwiftTripleDES.isValidKey(
            Data([0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
                  0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0x01,
                  0x45,0x67,0x89,0xAB,0xCD,0xEF,0x01,0x23]))) // 24
        XCTAssertFalse(PureSwiftTripleDES.isValidKey(
            Data([0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF]))) // 8
        XCTAssertFalse(PureSwiftTripleDES.isValidKey(Data()))
    }

    // MARK: - TripleDES : vecteurs externes (FIPS 46-3 / NIST SP 800-67)

    /// Cas dégénéré K1=K2=K3 : le 3DES équivaut à un DES simple.
    /// Vecteur FIPS 46-3 :
    ///   Key  = 0123456789ABCDEF
    ///   PT   = 0123456789ABCDEF
    ///   CT   = 85E813540F0AB405
    func testTripleDesDegenerateEqualsDes() {
        let crypto = PureSwiftTripleDES()
         let key: Data = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                          0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]) // 16 octets -> K3=K1
        let block: Data = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        let expected: Data = Data([0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05])

        let encrypted = crypto.tripleDesEcbEncrypt(key: key, block: block)
        XCTAssertEqual(encrypted, expected,
                       "Le cas dégénéré K1=K2=K3 doit reproduire le DES simple")

        let decrypted = crypto.tripleDesEcbDecrypt(key: key, block: encrypted)
        XCTAssertEqual(decrypted, block)
    }

    /// 3DES trois clés : aller-retour doit être neutre.
    func testTripleDesThreeKeysRoundTrip() {
        let crypto = PureSwiftTripleDES()
         let key: Data = Data([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
            0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23
        ]) // 24 octets
        let block: Data = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])

        let encrypted = crypto.tripleDesEcbEncrypt(key: key, block: block)
        let decrypted = crypto.tripleDesEcbDecrypt(key: key, block: encrypted)
        XCTAssertEqual(decrypted, block)
    }

    /// Clé 16 octets : la dérivée K3=K1 doit produire le même résultat qu'une clé 24 octets avec K3=K1 explicite.
    func testTripleDesKey16EqualsKey24WithK3K1() {
        let crypto = PureSwiftTripleDES()
         let key16: Data = Data([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01
        ])
         let key24: Data = Data([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF // K3 = K1
        ])
        let block: Data = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])

        let ct16 = crypto.tripleDesEcbEncrypt(key: key16, block: block)
        let ct24 = crypto.tripleDesEcbEncrypt(key: key24, block: block)
        XCTAssertEqual(ct16, ct24)
    }

    // MARK: - TripleDES-CBC-MAC ISO 9797-1

    func testTripleDesCbcMacDeterministic() {
        let crypto = PureSwiftTripleDES()
         let key: Data = Data([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01
        ])))
        let data: Data = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])

        let mac1 = crypto.tripleDesCbcMac(key: key, data: data)
        let mac2 = crypto.tripleDesCbcMac(key: key, data: data)
        XCTAssertEqual(mac1, mac2)
        XCTAssertEqual(mac1.count, 8)
    }

    func testTripleDesCbcMacDifferentDataDifferentMac() {
        let crypto = PureSwiftTripleDES()
        let key: Data = Data([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01
        ]
        let data1: Data = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        let data2: Data = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xF0])

        let mac1 = crypto.tripleDesCbcMac(key: key, data: data1)
        let mac2 = crypto.tripleDesCbcMac(key: key, data: data2)
        XCTAssertNotEqual(mac1, mac2)
    }

    func testTripleDesCbcMacPaddingMethod2() {
        let crypto = PureSwiftTripleDES()
        let key: Data = Data([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01
        ]
        // Données déjà alignées sur 8 octets : la méthode 2 ajoute un bloc de bourrage (0x80).
        let data8: Data = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        // Données non alignées (7 octets) : 0x80 puis un 0x00 pour atteindre 8.
        let data7: Data = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD])

        let mac8 = crypto.tripleDesCbcMac(key: key, data: data8)
        let mac7 = crypto.tripleDesCbcMac(key: key, data: data7)
        XCTAssertNotEqual(mac8, mac7,
                          "Le bourrage méthode 2 doit différencier les deux cas")
    }

    func testTripleDesRejectsWrongKeyLength() {
        let crypto = PureSwiftTripleDES()
        let key8: Data = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        let block: Data = Data([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])

        XCTAssertFalse(PureSwiftTripleDES.isValidKey(key8))
    }

    // MARK: - CalypsoMachine

    func testMachineSelectWrongAid() {
        var machine = CalypsoMachine()
        let wrongAid: Data = Data([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        let response = machine.handle(.selectAID(wrongAid))
        XCTAssertEqual(response, CalypsoResponse.fileNotFound)
        XCTAssertEqual(machine.state, .idle)
    }

    func testMachineSelectRightAid() {
        var machine = CalypsoMachine()
        let response = machine.handle(.selectAID(Data(calypsoAID)))
        XCTAssertEqual(response, CalypsoResponse.ok)
        XCTAssertEqual(machine.state, .aidSelected)
    }

    func testMachineSelectPrefixMatch() {
        var machine = CalypsoMachine()
        // SELECT par préfixe (forme tronquée) doit être accepté.
        let prefixAid: Data = Data(calypsoAID.prefix(8))
        let response = machine.handle(.selectAID(prefixAid))
        XCTAssertEqual(response, CalypsoResponse.ok)
        XCTAssertEqual(machine.state, .aidSelected)
    }

    func testMachineSelectLongerAidMatch() {
        var machine = CalypsoMachine()
        // SELECT avec un AID plus long qui commence par calypsoAID doit être accepté.
        var longerAid = calypsoAID
        longerAid.append(0x00)
        longerAid.append(0x01)
        let response = machine.handle(.selectAID(Data(longerAid)))
        XCTAssertEqual(response, CalypsoResponse.ok)
        XCTAssertEqual(machine.state, .aidSelected)
    }

    func testMachineReadRecordBeforeSessionIs6982() {
        var machine = CalypsoMachine()
        _ = machine.handle(.selectAID(Data(calypsoAID)))
        let response = machine.handle(.readRecord(p1: 0x01, p2: 0x04))
        XCTAssertEqual(response, CalypsoResponse.accessDenied)
    }

    func testMachineOpenSecureSessionStoresChallengeNotKey() {
        var machine = CalypsoMachine()
        _ = machine.handle(.selectAID(Data(calypsoAID)))
        let challenge: Data = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        let response = machine.handle(.openSecureSession(p1: 0x8A, p2: 0x30, data: challenge))
        XCTAssertEqual(response, CalypsoResponse.ok)
        XCTAssertEqual(machine.state, .secureSessionOpen)
        XCTAssertEqual(machine.sessionAlgorithm, 0x8A)
        XCTAssertEqual(machine.sessionKeyIndex, 0x30)
        XCTAssertEqual(machine.challenge, challenge)
        XCTAssertEqual(machine.selectedAID, Data(calypsoAID))
    }

    func testMachineReset() {
        var machine = CalypsoMachine()
        _ = machine.handle(.selectAID(Data(calypsoAID)))
        let challenge: Data = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        _ = machine.handle(.openSecureSession(p1: 0x00, p2: 0x00, data: challenge))
        XCTAssertEqual(machine.state, .secureSessionOpen)
        machine.reset()
        XCTAssertEqual(machine.state, .idle)
        XCTAssertNil(machine.selectedAID)
        XCTAssertNil(machine.sessionAlgorithm)
        XCTAssertNil(machine.sessionKeyIndex)
        XCTAssertNil(machine.challenge)
    }

    func testMachineOpenSecureSessionWithoutSelect() {
        var machine = CalypsoMachine()
        let response = machine.handle(.openSecureSession(p1: 0x00, p2: 0x00, data: Data()))
        XCTAssertEqual(response, CalypsoResponse.accessDenied)
    }
}
