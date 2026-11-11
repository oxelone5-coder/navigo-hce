# Navigo HCE — démarches administratives (étape B, C, D)

## Ordre des démarches

1. **Créer la structure** : guichet unique INPI, micro-entreprise, gratuit, ~15 min.
2. **Demander le D-U-N-S** : via Apple, gratuit, 1 à 2 semaines.
3. **Souscrire l'Apple Developer Program (organisation)** : 99 €/an.
   - Un compte individuel ne donne pas accès à l'entitlement HCE.
4. **Demander l'entitlement HCE** : `developer.apple.com/contact/request/hce-entitlement`
   - Use case : closed-loop transit
   - AID : `A0000005591010FFFFFFFF8900000100`
   - Demander la version développement d'abord, puis distribution si TestFlight.
5. **Créer le projet Xcode** : iOS App → SwiftUI, nom `NavigoHCE`, bundle ID `fr.TONNOM.navigohce`.
6. **Ajouter la capability NFC Tag Reading**.
7. **Définir CODE_SIGN_ENTITLEMENTS** = `NavigoHCE/NavigoHCE.entitlements`.
8. **Ajouter les clés Info.plist** (NFCReaderUsageDescription, etc.).

## Formulaire HCE (pré-rempli)

- URL : `developer.apple.com/contact/request/hce-entitlement`
- Use case : closed-loop transit
- AID : `A0000005591010FFFFFFFF8900000100`
- Version demandée : développement (puis distribution si TestFlight)

## D-U-N-S

- Gratuit, demandé via Apple.
- Délai : 1 à 2 semaines.

## INPI / micro-entreprise

- Guichet unique INPI, gratuit, ~15 minutes.

## Apple Developer Program

- Formule organisation, 99 €/an.
