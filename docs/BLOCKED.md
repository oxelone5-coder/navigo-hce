# Navigo HCE — bloqueurs (BLOCKED.md)

## Étape en cours
Point 1 du plan : paquet Swift `Packages/NavigoCore` (Hex, decodeAPDU, machine d'état Calypso, 3DES-CBC-MAC en Swift pur).

## Vérification reportée
- Aucun toolchain Swift installé sur cette machine Windows (`swift --version` introuvable, `xcodebuild` introuvable).
- `swift test` dans `Packages/NavigoCore` n'a pas pu être exécuté.
- Les tests sont écrits dans `Packages/NavigoCore/Tests/NavigoCoreTests/NavigoCoreTests.swift` et attendent un hôte avec toolchain Swift (macOS ou Windows avec toolchain officiel) pour passer le gate `swift test`.

## Étape A (VM macOS) non démarrée
- Aucune VM macOS disponible, donc pas de SSH vers une VM.
- `docs/SPEC.md` existe maintenant.
- L'étape A (ISO macOS, VMware, Unlocker, installation macOS, Xcode) relève de l'utilisateur côté Windows (VT-x BIOS, Hyper-V désactivé, compte Broadcom, Unlocker admin, installation macOS).

## Points en suspens avant l'étape I
- Confirmer dans CalypsoFuncSpecification.pdf que la chaîne CBC est en DES simple par bloc, pas en 3DES par bloc.
- Récupérer les clés réseau réelles (dossier Pirates Magazine, acbm.com, CardPeek, Metrodroid) une fois l'entitlement obtenu.

## Règle
Si une étape échoue : diagnostic ici, pas de contournement. Ne jamais modifier `docs/SPEC.md`.
