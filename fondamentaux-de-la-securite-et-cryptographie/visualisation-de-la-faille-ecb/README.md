# 🔐 Fondamentaux de la Sécurité et Cryptographie

**Module:** Fondamentaux de la Sécurité et Cryptographie  
**Établissement:** ISGA Marrakech - École d'Ingénieurs  
**Auteur:** Farah  
**Date:** Janvier 2026

---

## 📋 Table des Matières

- [Vue d'ensemble](#-vue-densemble)
- [Prérequis](#-prérequis)
- [TP1: Attaque du Chiffre de César](#-tp1-attaque-du-chiffre-de-césar)
- [TP2: Manipulation AES avec OpenSSL](#-tp2-manipulation-aes-avec-openssl)
- [TP3: Visualisation de la faille ECB](#-tp3-visualisation-de-la-faille-ecb)
- [Installation](#-installation)
- [Structure des fichiers](#-structure-des-fichiers)
- [Pour le rapport](#-pour-le-rapport)
- [Troubleshooting](#-troubleshooting)
- [Références](#-références)

---

## 🎯 Vue d'ensemble

Ce repository contient les travaux pratiques couvrant:

1. **Cryptographie classique** - Chiffre de César et ses vulnérabilités
2. **Cryptographie moderne** - AES-256 et l'importance du Salt
3. **Modes d'opération** - ECB vs CBC (démonstration visuelle)

### Objectifs pédagogiques

✅ Comprendre pourquoi ne pas créer son propre algorithme  
✅ Maîtriser le chiffrement symétrique (AES)  
✅ Découvrir l'importance du mode d'opération  
✅ Analyser les vulnérabilités des algorithmes faibles

---

## 💻 Prérequis

### Système
- Linux (Debian/Ubuntu) - **RECOMMANDÉ**
- Windows avec WSL2 ou macOS

### Logiciels
```bash
python3 --version  # 3.8+
openssl version    # 1.1.1+
curl --version
```

### Installation (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install -y python3 openssl curl
```

---

## 🔑 TP1: Attaque du Chiffre de César

### Description
Démonstration des vulnérabilités du César via:
- **Force Brute** (26 clés)
- **Analyse de Fréquence** (Chi-carré)

### Utilisation rapide
```bash
python3 tp1_cesar.py
# Menu interactif avec 6 modes
```

### Modes disponibles
1. TP1 automatique (message du prof)
2. Chiffrer un message
3. Déchiffrer (avec clé)
4. Cryptanalyse (sans clé) ⭐
5. Exemples
6. Aide

### Résultats TP1
- Message: `YHWL YLGL YLFL`
- Clé détectée: `3`
- Déchiffré: `VETI VIDI VICI`
- Note: Faute de frappe dans le PDF (W→Q)

### Techniques utilisées
- **Chi-carré (χ²)**: Compare fréquences
- **Index Coïncidence**: Détecte langue naturelle
- **Détection mots**: Base de données FR/EN/Latin

---

## 🔒 TP2: Manipulation AES avec OpenSSL

### Description
Comprendre AES-256-CBC et le **Salt**.

### Commandes essentielles

**Chiffrer:**
```bash
echo "Mon secret bancaire est 1234" > secret.txt
openssl enc -aes-256-cbc -in secret.txt -out secret.enc -pbkdf2
```

**Déchiffrer:**
```bash
openssl enc -d -aes-256-cbc -in secret.enc -out decrypt.txt -pbkdf2
```

**Expérience du Salt:**
```bash
# Chiffrer 2 fois
openssl enc -aes-256-cbc -in secret.txt -out secret1.enc -pbkdf2
openssl enc -aes-256-cbc -in secret.txt -out secret2.enc -pbkdf2

# Comparer
md5sum secret1.enc secret2.enc
# Résultat: MD5 DIFFÉRENTS!
```

### Observations clés
- ✅ Même fichier + même mot de passe → fichiers différents
- ✅ Raison: Salt aléatoire (8 octets après "Salted__")
- ✅ Protection contre dictionnaires et analyse

### Comparaison

| Critère | César | AES-256-CBC |
|---------|-------|-------------|
| Clés | 26 | 2^256 |
| Salt | ❌ | ✅ |
| Même→Même | ✅ Mauvais | ❌ Bon |
| Force brute | <1ms | >Âge univers |
| Production | ❌ | ✅ |

---

## 🐧 TP3: Visualisation de la faille ECB

### Description
Démonstration visuelle: ECB préserve les motifs, CBC les détruit.

### Utilisation automatique
```bash
chmod +x tp3_ecb_penguin.sh
./tp3_ecb_penguin.sh
```

Le script fait tout:
1. Télécharge l'image Tux
2. Extrait en-tête/corps
3. Chiffre en ECB
4. Chiffre en CBC
5. Recrée les images
6. Explique les résultats

### Utilisation manuelle
```bash
# Télécharger
curl -L -o tux.bmp https://raw.githubusercontent.com/tkeliris/ecb-penguin/3910bccd6924eb6c632560adeb9df4ce380c0b92/tux_clear.bmp

# Extraire
head -c 54 tux.bmp > header.bin
tail -c +55 tux.bmp > body.bin

# Chiffrer ECB
KEY="31323334353637383930313233343536"
openssl enc -aes-128-ecb -in body.bin -out body_ecb.enc -K $KEY -nosalt

# Chiffrer CBC
IV="30303030303030303030303030303030"
openssl enc -aes-128-cbc -in body.bin -out body_cbc.enc -K $KEY -iv $IV -nosalt

# Reconstruire
cat header.bin body_ecb.enc > tux_ecb.bmp
cat header.bin body_cbc.enc > tux_cbc.bmp
```

### Résultats visuels

**tux.bmp** (Original)
- 🐧 Pingouin visible
- Couleurs nettes

**tux_ecb.bmp** (ECB - DANGEREUX)
- ⚠️ Pingouin ENCORE visible!
- Contours reconnaissables
- ❌ Structure préservée

**tux_cbc.bmp** (CBC - SÉCURISÉ)
- ✅ Bruit blanc total
- Aucun motif visible
- ✅ Totalement illisible

### Explication

**Mode ECB:**
```
Bloc 1 → [AES] → Chiffré 1
Bloc 2 → [AES] → Chiffré 2  ← Indépendant
Bloc 3 → [AES] → Chiffré 3

❌ Bloc identique → Chiffré identique
```

**Mode CBC:**
```
Bloc 1 → [XOR+AES] → Chiffré 1
Bloc 2 → [XOR+AES] ← Chiffré 1  ← Chaîné
Bloc 3 → [XOR+AES] ← Chiffré 2

✅ Chaque bloc dépend du précédent
```

### Conclusion TP3
> "Bon algorithme (AES) + Mauvais mode (ECB) = Dangereux"

**À utiliser:** CBC, GCM, CTR  
**À bannir:** ECB

---

## 🔧 Installation

```bash
# Cloner
#git clone https://github.com/FarahElAlem/fondamentaux-de-la-securite-et-cryptographie/visualisation-de-la-faille-ecb
#cd fondamentaux-de-la-securite-et-cryptographie/visualisation-de-la-faille-ecb


---

## 📁 Structure des fichiers

```
.
├── README.md                    ⭐ Ce fichier
│
├── TP1/
│   ├── tp1_cesar.py            # Script principal interactif
│   ├── caesar_cipher_attack.py # Version avancée
│   ├── advanced_examples.py    # 8 exemples
│   ├── test_caesar.py          # Tests (50+)
│   └── RAPPORT_TECHNIQUE.md    # Rapport complet
│
├── TP2/
│   ├── secret.txt
│   ├── secret.enc
│   └── decrypt.txt
│
├── TP3/
│   ├── tp3_ecb_penguin.sh      ⭐ Script auto
│   ├── tux.bmp                 # Original
│   ├── tux_ecb.bmp             # ECB (visible)
│   └── tux_cbc.bmp             # CBC (bruit)
│
└── Documentation/
    ├── GUIDE_UTILISATION.py
    └── requirements.txt
```

---

## 📝 Pour le rapport

### TP1 - Points clés
1. Formules mathématiques (C = P+k mod 26)
2. Code Python commenté
3. Graphiques de fréquences
4. Tableau comparatif César/AES
5. Temps d'exécution (<1ms)

### TP2 - Points clés
1. Captures MD5 différents
2. Hexdump montrant "Salted__"
3. Explication PBKDF2 et Salt
4. Tableau comparatif
5. Avantages du Salt

### TP3 - Points clés
1. **3 images côte à côte** (crucial!)
2. Schémas ECB vs CBC
3. Explication des motifs
4. Conclusion: Importance du mode
5. Recommandations (CBC, GCM)

---

## 🐛 Troubleshooting

**OpenSSL non trouvé:**
```bash
sudo apt install openssl
```

**Image ne se télécharge pas:**
```bash
# Vérifier internet
ping google.com

# Forcer redirect
curl -L -o tux.bmp [URL]
```

**Voir les images .bmp:**
```bash
# Linux
sudo apt install imagemagick
display tux_ecb.bmp

# Ou transférer vers Windows
scp user@ip:~/tp3/*.bmp .
```

**Permission refusée:**
```bash
chmod +x tp3_ecb_penguin.sh
```

---

## 📚 Références

### Documentation
- [OpenSSL Docs](https://www.openssl.org/docs/)
- [NIST AES Standard](https://csrc.nist.gov/publications/detail/fips/197/final)
- [Python Cryptography](https://cryptography.io/)

### Articles
1. Kerckhoffs (1883) - "La cryptographie militaire"
2. Shannon (1949) - "Communication Theory of Secrecy Systems"
3. NIST FIPS 197 (2001) - "AES Standard"

### Ressources
- Cours ISGA Marrakech
- [ECB Penguin - GitHub](https://github.com/tkeliris/ecb-penguin)
- [Frequency Analysis - Wikipedia](https://en.wikipedia.org/wiki/Frequency_analysis)

---

## 👤 Auteur

**Farah**  
ISGA Marrakech

---

## ⚠️ Avertissement

**Usage académique uniquement!**

- ❌ César: Ne JAMAIS utiliser en production
- ❌ ECB: Ne JAMAIS utiliser en production
- ✅ AES-CBC/GCM: Standards recommandés
- ✅ Bibliothèques éprouvées uniquement

---

*Dernière mise à jour: Janvier 2026*
