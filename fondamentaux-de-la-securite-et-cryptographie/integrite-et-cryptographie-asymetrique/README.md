# Échange de Clés Diffie-Hellman - Simulation Interactive

Une simulation web interactive de l'algorithme d'échange de clés Diffie-Hellman, permettant de visualiser étape par étape comment deux parties peuvent établir un secret partagé sur un canal public non sécurisé.

## Description

Cet outil pédagogique démontre le fonctionnement de l'algorithme Diffie-Hellman (1976), qui résout le problème fondamental de l'échange de clés en cryptographie symétrique. Il permet de comprendre comment Alice et Bob peuvent générer un secret commun sans jamais l'échanger directement, même si toutes leurs communications sont interceptées.

## Fonctionnalités

- **Interface simple et épurée** : Design minimaliste centré sur la compréhension
- **Calculs en temps réel** : Visualisation immédiate des résultats
- **Étapes détaillées** : Chaque phase de l'algorithme est expliquée
- **Valeurs personnalisables** : Possibilité de tester avec différents paramètres
- **Responsive** : Fonctionne sur desktop et mobile

## Utilisation

### Lancement local

1. **Cloner ou télécharger** le fichier `diffie_hellman.html`

2. **Démarrer un serveur HTTP local** (optionnel mais recommandé) :
```bash
   python3 -m http.server 8080
```

3. **Ouvrir dans le navigateur** :
   - Serveur local : `http://localhost:8080/diffie_hellman.html`
   - Ou simplement double-cliquer sur le fichier HTML

### Paramètres

- **p (nombre premier)** : Module commun public (ex: 23, 47, 97)
- **g (générateur)** : Base commune publique (ex: 2, 5, 7)
- **a (clé privée d'Alice)** : Valeur secrète choisie par Alice
- **b (clé privée de Bob)** : Valeur secrète choisie par Bob

### Valeurs par défaut

Les valeurs de démonstration pré-remplies sont :
- p = 23
- g = 5
- a = 6
- b = 15

Ces valeurs produisent un secret partagé facilement vérifiable.

## Comment ça fonctionne

### Principe mathématique

L'algorithme repose sur la difficulté du **problème du logarithme discret** :

1. **Accord public** : Alice et Bob s'accordent sur `p` (nombre premier) et `g` (générateur)

2. **Génération des clés privées** :
   - Alice choisit secrètement `a`
   - Bob choisit secrètement `b`

3. **Calcul des clés publiques** :
   - Alice calcule `A = g^a mod p` et l'envoie à Bob
   - Bob calcule `B = g^b mod p` et l'envoie à Alice

4. **Calcul du secret partagé** :
   - Alice calcule `s = B^a mod p`
   - Bob calcule `s = A^b mod p`
   - Les deux obtiennent la même valeur `s` !

### Sécurité

- **Ce qui est public** : p, g, A, B
- **Ce qui est secret** : a, b, s
- **Difficulté** : Même en connaissant p, g, A et B, il est computationnellement impossible de retrouver a ou b (et donc s)

## Exemple de calcul

Avec les valeurs par défaut :
```
Paramètres publics :
p = 23, g = 5

Clés privées (secrètes) :
Alice : a = 6
Bob   : b = 15

Clés publiques :
Alice calcule : A = 5^6  mod 23 = 8
Bob calcule   : B = 5^15 mod 23 = 19

Secret partagé :
Alice calcule : s = 19^6  mod 23 = 2
Bob calcule   : s = 8^15  mod 23 = 2

✓ Secret partagé : s = 2
```

## Contexte historique

- **Inventé en 1976** par Whitfield Diffie et Martin Hellman
- **Premier algorithme** d'échange de clés à clé publique
- **Révolution cryptographique** : Résout le problème de distribution des clés
- **Utilisé aujourd'hui** : TLS/SSL (HTTPS), SSH, VPN, Signal, WhatsApp

## Applications pratiques

L'algorithme Diffie-Hellman est utilisé dans :

- **HTTPS** : Établissement de connexions sécurisées sur le web
- **SSH** : Connexions sécurisées aux serveurs
- **VPN** : Tunnels chiffrés (IPSec, WireGuard)
- **Messagerie** : Signal, WhatsApp (variante ECDH)
- **Cryptomonnaies** : Échange de clés pour transactions

## Limitations et variantes

### Limitations de cette démo

- **Petits nombres** : Pour faciliter la compréhension (dans la réalité, p > 2048 bits)
- **Pas de protection MITM** : Vulnérable à l'attaque de l'homme du milieu sans authentification
- **DH classique** : Version éducative (en production on utilise ECDH - Elliptic Curve DH)

### Variantes modernes

- **ECDH** : Diffie-Hellman sur courbes elliptiques (plus efficace)
- **DHE** : DH Ephemeral (nouvelles clés à chaque session)
- **X25519** : Implémentation moderne utilisée par Signal

## Prérequis techniques

- Navigateur web moderne (Chrome, Firefox, Safari, Edge)
- JavaScript activé
- Aucune bibliothèque externe requise

## Structure du code
```
diffie_hellman.html
├── HTML : Structure de la page
├── CSS : Styles (design minimaliste)
└── JavaScript : Logique de calcul
    ├── modPow() : Exponentiation modulaire
    ├── calculate() : Calcul de l'échange DH
    └── reset() : Réinitialisation du formulaire
```

## Ressources complémentaires

### Articles et documentation

- [RFC 2631 - Diffie-Hellman Key Agreement](https://tools.ietf.org/html/rfc2631)
- [Wikipedia - Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)
- [Cours de cryptographie - Khan Academy](https://www.khanacademy.org/computing/computer-science/cryptography)

### Outils similaires

- [dcode.fr - Diffie-Hellman](https://www.dcode.fr/echange-cle-diffie-hellman)
- [CrypTool](https://www.cryptool.org/)

## Auteur

Projet créé dans le cadre du cours **Sécurité et Cryptographie** - Semaine 2
Module : Fondamentaux de la Sécurité et Cryptographie
ISGA Marrakech - 2025

## Licence

Ce projet est à usage éducatif.

## Notes de développement

- **Version** : 1.0
- **Date de création** : Janvier 2025
- **Compatibilité** : Tous navigateurs modernes
- **Dépendances** : Aucune

## FAQ

**Q : Pourquoi mes valeurs ne fonctionnent pas ?**  
R : Assurez-vous que p est un nombre premier et que a et b sont inférieurs à p.

**Q : Peut-on utiliser de très grands nombres ?**  
R : Cette version utilise les nombres JavaScript standards. Pour de très grands nombres (>2^53), il faudrait utiliser BigInt.

**Q : Est-ce sécurisé pour de vraies communications ?**  
R : Non, cette version est éducative. En production, utilisez des bibliothèques cryptographiques certifiées avec p > 2048 bits.

**Q : Qu'est-ce qui empêche Ève de calculer le secret ?**  
R : Le problème du logarithme discret : étant donné g^x mod p, il est très difficile de retrouver x.

---

**Pour toute question ou suggestion, n'hésitez pas à contribuer !**
