# Navigo HCE — invariants

## But
Émuler une carte Calypso ISO 14443-4 sur iPhone 14 Pro pour valider aux
portiques. La carte physique reste active, rien n'est écrit dessus.

## AID unique
A0000005591010FFFFFFFF8900000100

## Deux targets, jamais fusionnés
- NavigoHCE : émulation, entitlement HCE, pas de lecture.
- NavigoDump : lecture, pas d'entitlement HCE, pas d'émulation.
Un seul des deux tourne à la fois sur l'appareil.

## Entitlements NavigoHCE
com.apple.developer.nfc.hce = true
com.apple.developer.nfc.hce.iso7816.select-identifier-prefixes = [AID]
com.apple.developer.nfc.hce.default-contactless-app = true
(retirer default-contactless-app si la re-signature échoue)

## Clés Info.plist NavigoDump
NFCReaderUsageDescription, UIFileSharingEnabled,
LSSupportsOpeningDocumentsInPlace,
com.apple.developer.nfc.readersession.iso7816.select-identifiers = [AID]

## Arborescence
Packages/NavigoCore/   logique pure, sans CoreNFC
NavigoHCE/             Emulator.swift, ContentView.swift
NavigoDump/            CardReader.swift, ReaderView.swift
docs/                  SPEC.md, ADMIN.md, BLOCKED.md
project.yml            XcodeGen

## NavigoCore
Hex, decodeAPDU, machine d'état (SELECT AID, READ RECORD, OPEN SECURE
SESSION), 3DES-CBC-MAC derrière un protocole. Testable sur macOS.

## 3DES-CBC-MAC (Calypso)
- Algorithme : ISO 9797-1 MAC algorithme 3 — CBC avec K1 sur tous les blocs,
  puis déchiffrement du dernier bloc MAC avec K2, puis chiffrement avec K1.
- Bourrage : méthode 2 (0x80 puis 0x00 jusqu'à l'alignement sur 8 octets),
  toujours appliqué même si les données sont déjà alignées.
- Longueur de clé : 16 octets (TDEA à deux clés, K1‖K2‖K1, donc K3 = K1).
- IV : nul.
- À confirmer dans CalypsoFuncSpecification.pdf avant l'étape I :
  la chaîne CBC est en DES simple par bloc, pas en 3DES par bloc (variante
  selon les implémentations).

## Résultats attendus, pas des échecs
- 6982 sur fichiers protégés : normal, relève de l'étape I.
- 6A82 sur SELECT : l'AID déclaré ne correspond pas, ajuster le préfixe.
- Le balayage SFI va de 1 à 30, 4 enregistrements, puis s'arrête.

## Interdits
- Inventer un nom d'API CoreNFC.
- Écrire sur la carte.
- Changer la spec pour faire passer un test.
- Fusionner les deux targets.
