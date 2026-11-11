import Foundation

/// État de la machine Calypso.
public enum CalypsoState: Equatable {
    case idle
    case aidSelected
    case secureSessionOpen
}

/// Événements reçus du lecteur.
public enum CalypsoEvent: Equatable {
    case selectAID(Data)
    case readRecord(p1: UInt8, p2: UInt8)
    case openSecureSession(p1: UInt8, p2: UInt8, data: Data)
}

/// Réponse à envoyer au lecteur.
public struct CalypsoResponse: Equatable {
    public let data: Data
    public let sw1: UInt8
    public let sw2: UInt8

    public init(data: Data = Data(), sw1: UInt8 = 0x90, sw2: UInt8 = 0x00) {
        self.data = data
        self.sw1 = sw1
        self.sw2 = sw2
    }

    public static let ok = CalypsoResponse()
    public static let accessDenied = CalypsoResponse(sw1: 0x69, sw2: 0x82)
    public static let fileNotFound = CalypsoResponse(sw1: 0x6A, sw2: 0x82)
    public static let recordNotFound = CalypsoResponse(sw1: 0x6A, sw2: 0x83)
}

/// Machine d'état Calypso : modélise le protocole ISO 14443-4 côté carte.
public struct CalypsoMachine {
    public var state: CalypsoState
    public var selectedAID: Data?
    public var sessionAlgorithm: UInt8?
    public var sessionKeyIndex: UInt8?
    public var challenge: Data?

    public init() {
        self.state = .idle
        self.selectedAID = nil
        self.sessionAlgorithm = nil
        self.sessionKeyIndex = nil
        self.challenge = nil
    }

    public mutating func reset() {
        state = .idle
        selectedAID = nil
        sessionAlgorithm = nil
        sessionKeyIndex = nil
        challenge = nil
    }

    /// Traite un événement et retourne la réponse APDU.
    public mutating func handle(_ event: CalypsoEvent) -> CalypsoResponse {
        switch event {
        case .selectAID(let aid):
            return handleSelectAID(aid)
        case .readRecord(let p1, let p2):
            return handleReadRecord(p1: p1, p2: p2)
        case .openSecureSession(let p1, let p2, let data):
            return handleOpenSecureSession(p1: p1, p2: p2, data: data)
        }
    }

    private mutating func handleSelectAID(_ aid: Data) -> CalypsoResponse {
        let bytes = [UInt8](aid)
        guard !bytes.isEmpty,
              calypsoAID.starts(with: bytes) || bytes.starts(with: calypsoAID)
        else { return .fileNotFound }
        state = .aidSelected
        selectedAID = aid
        return .ok
    }

    private mutating func handleReadRecord(p1: UInt8, p2: UInt8) -> CalypsoResponse {
        guard state != .idle else { return .accessDenied }
        // Étape E : tout est protégé. Étape H : brancher la table de dump ici.
        return .accessDenied
    }

    private mutating func handleOpenSecureSession(p1: UInt8, p2: UInt8, data: Data) -> CalypsoResponse {
        guard state == .aidSelected else { return .accessDenied }
        state = .secureSessionOpen
        sessionAlgorithm = p1
        sessionKeyIndex = p2
        challenge = data
        return .ok
    }
}
