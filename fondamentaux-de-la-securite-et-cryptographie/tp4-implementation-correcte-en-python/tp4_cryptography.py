#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════════════
    TP4 - CRYPTOGRAPHIE MODERNE AVEC PYTHON - VERSION 2.0
    Bibliothèque: cryptography (Standard industriel)
    
    Module: Fondamentaux de la Sécurité et Cryptographie
    ISGA Marrakech
    
    Auteur: Farah El Alem
    Version: 2.0 - COMPLÈTE ET INTERACTIVE
═══════════════════════════════════════════════════════════════════════════

✅ Modes interactifs (chiffrer/déchiffrer ses propres messages)
✅ Chiffrement/déchiffrement de fichiers
✅ Sauvegarde/chargement de messages chiffrés
✅ Comparaison temps réel César vs AES-GCM
✅ Export/Import de clés
✅ Statistiques et benchmarks
"""

import os
import sys
import json
import time
import base64
import secrets
from pathlib import Path
from typing import Tuple, Optional, Dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag


# ═══════════════════════════════════════════════════════════════════════════
#                           CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

KEY_SIZE = 32
NONCE_SIZE = 12
SALT_SIZE = 16
PBKDF2_ITERATIONS = 600000

# Dossiers de travail
SAVE_DIR = Path("encrypted_messages")
KEYS_DIR = Path("keys")

# Créer les dossiers
SAVE_DIR.mkdir(exist_ok=True)
KEYS_DIR.mkdir(exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════════
#                    FONCTIONS CRYPTOGRAPHIQUES (V1.0)
# ═══════════════════════════════════════════════════════════════════════════

def generer_cle_aleatoire() -> bytes:
    """Génère une clé AES-256 cryptographiquement sécurisée"""
    return secrets.token_bytes(KEY_SIZE)


def deriver_cle_depuis_mot_de_passe(mot_de_passe: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Dérive une clé depuis un mot de passe avec PBKDF2"""
    if salt is None:
        salt = secrets.token_bytes(SALT_SIZE)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    
    cle = kdf.derive(mot_de_passe.encode('utf-8'))
    return cle, salt


def chiffrer_aes_gcm(message: str, cle: bytes, donnees_additionnelles: Optional[str] = None) -> dict:
    """Chiffre un message avec AES-256-GCM"""
    if len(cle) != KEY_SIZE:
        raise ValueError(f"La clé doit faire {KEY_SIZE} octets")
    
    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(cle)
    aad = donnees_additionnelles.encode('utf-8') if donnees_additionnelles else None
    
    message_bytes = message.encode('utf-8')
    chiffre = aesgcm.encrypt(nonce, message_bytes, aad)
    
    return {
        'chiffre': chiffre,
        'nonce': nonce,
        'aad': donnees_additionnelles
    }


def dechiffrer_aes_gcm(donnees_chiffrees: dict, cle: bytes) -> str:
    """Déchiffre un message AES-256-GCM"""
    if len(cle) != KEY_SIZE:
        raise ValueError(f"La clé doit faire {KEY_SIZE} octets")
    
    chiffre = donnees_chiffrees['chiffre']
    nonce = donnees_chiffrees['nonce']
    aad_str = donnees_chiffrees.get('aad')
    aad = aad_str.encode('utf-8') if aad_str else None
    
    aesgcm = AESGCM(cle)
    
    try:
        message_bytes = aesgcm.decrypt(nonce, chiffre, aad)
        return message_bytes.decode('utf-8')
    except InvalidTag:
        raise InvalidTag("ERREUR: Le message a été altéré ou la clé est incorrecte!")


# ═══════════════════════════════════════════════════════════════════════════
#                    NOUVELLES FONCTIONS V2.0 - FICHIERS
# ═══════════════════════════════════════════════════════════════════════════

def chiffrer_fichier(fichier_entree: str, cle: bytes, fichier_sortie: Optional[str] = None) -> str:
    """
    Chiffre un fichier avec AES-256-GCM
    
    Args:
        fichier_entree: Chemin du fichier à chiffrer
        cle: Clé AES-256
        fichier_sortie: Chemin du fichier chiffré (optionnel)
        
    Returns:
        str: Chemin du fichier chiffré créé
    """
    # Lire le fichier
    with open(fichier_entree, 'rb') as f:
        contenu = f.read()
    
    # Générer nonce
    nonce = secrets.token_bytes(NONCE_SIZE)
    
    # Chiffrer
    aesgcm = AESGCM(cle)
    chiffre = aesgcm.encrypt(nonce, contenu, None)
    
    # Nom du fichier de sortie
    if fichier_sortie is None:
        fichier_sortie = f"{fichier_entree}.encrypted"
    
    # Écrire: nonce (12 octets) + chiffré
    with open(fichier_sortie, 'wb') as f:
        f.write(nonce)
        f.write(chiffre)
    
    return fichier_sortie


def dechiffrer_fichier(fichier_chiffre: str, cle: bytes, fichier_sortie: Optional[str] = None) -> str:
    """
    Déchiffre un fichier AES-256-GCM
    
    Args:
        fichier_chiffre: Chemin du fichier chiffré
        cle: Clé AES-256
        fichier_sortie: Chemin du fichier déchiffré (optionnel)
        
    Returns:
        str: Chemin du fichier déchiffré créé
    """
    # Lire le fichier
    with open(fichier_chiffre, 'rb') as f:
        nonce = f.read(NONCE_SIZE)
        chiffre = f.read()
    
    # Déchiffrer
    aesgcm = AESGCM(cle)
    
    try:
        contenu = aesgcm.decrypt(nonce, chiffre, None)
    except InvalidTag:
        raise InvalidTag("ERREUR: Le fichier a été altéré ou la clé est incorrecte!")
    
    # Nom du fichier de sortie
    if fichier_sortie is None:
        if fichier_chiffre.endswith('.encrypted'):
            fichier_sortie = fichier_chiffre[:-10]  # Enlever '.encrypted'
        else:
            fichier_sortie = f"{fichier_chiffre}.decrypted"
    
    # Écrire
    with open(fichier_sortie, 'wb') as f:
        f.write(contenu)
    
    return fichier_sortie


# ═══════════════════════════════════════════════════════════════════════════
#                    NOUVELLES FONCTIONS V2.0 - SAUVEGARDE
# ═══════════════════════════════════════════════════════════════════════════

def sauvegarder_message_chiffre(nom: str, donnees_chiffrees: dict, cle: bytes) -> str:
    """
    Sauvegarde un message chiffré dans un fichier JSON
    
    Args:
        nom: Nom du message (utilisé pour le fichier)
        donnees_chiffrees: Dict retourné par chiffrer_aes_gcm()
        cle: Clé utilisée (sauvegardée séparément)
        
    Returns:
        str: Chemin du fichier créé
    """
    # Préparer les données pour JSON
    data = {
        'nom': nom,
        'timestamp': time.time(),
        'chiffre': base64.b64encode(donnees_chiffrees['chiffre']).decode('utf-8'),
        'nonce': base64.b64encode(donnees_chiffrees['nonce']).decode('utf-8'),
        'aad': donnees_chiffrees.get('aad'),
        'cle': base64.b64encode(cle).decode('utf-8')
    }
    
    # Nom du fichier
    fichier = SAVE_DIR / f"{nom.replace(' ', '_')}.json"
    
    # Sauvegarder
    with open(fichier, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    return str(fichier)


def charger_message_chiffre(fichier: str) -> Tuple[dict, bytes]:
    """
    Charge un message chiffré depuis un fichier JSON
    
    Args:
        fichier: Chemin du fichier JSON
        
    Returns:
        Tuple[dict, bytes]: (donnees_chiffrees, cle)
    """
    with open(fichier, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Reconstruire les données
    donnees_chiffrees = {
        'chiffre': base64.b64decode(data['chiffre']),
        'nonce': base64.b64decode(data['nonce']),
        'aad': data.get('aad')
    }
    
    cle = base64.b64decode(data['cle'])
    
    return donnees_chiffrees, cle


def lister_messages_sauvegardes() -> list:
    """Liste tous les messages chiffrés sauvegardés"""
    fichiers = list(SAVE_DIR.glob("*.json"))
    
    messages = []
    for f in fichiers:
        try:
            with open(f, 'r', encoding='utf-8') as file:
                data = json.load(file)
                messages.append({
                    'fichier': f.name,
                    'nom': data['nom'],
                    'date': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data['timestamp']))
                })
        except:
            pass
    
    return messages


# ═══════════════════════════════════════════════════════════════════════════
#                    NOUVELLES FONCTIONS V2.0 - GESTION CLÉS
# ═══════════════════════════════════════════════════════════════════════════

def sauvegarder_cle(nom: str, cle: bytes) -> str:
    """Sauvegarde une clé dans un fichier"""
    fichier = KEYS_DIR / f"{nom}.key"
    
    data = {
        'nom': nom,
        'cle': base64.b64encode(cle).decode('utf-8'),
        'taille': len(cle) * 8,
        'timestamp': time.time()
    }
    
    with open(fichier, 'w') as f:
        json.dump(data, f, indent=2)
    
    return str(fichier)


def charger_cle(nom: str) -> bytes:
    """Charge une clé depuis un fichier"""
    fichier = KEYS_DIR / f"{nom}.key"
    
    with open(fichier, 'r') as f:
        data = json.load(f)
    
    return base64.b64decode(data['cle'])


def lister_cles() -> list:
    """Liste toutes les clés sauvegardées"""
    fichiers = list(KEYS_DIR.glob("*.key"))
    
    cles = []
    for f in fichiers:
        try:
            with open(f, 'r') as file:
                data = json.load(file)
                cles.append({
                    'fichier': f.name,
                    'nom': data['nom'],
                    'taille': data['taille'],
                    'date': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data['timestamp']))
                })
        except:
            pass
    
    return cles


# ═══════════════════════════════════════════════════════════════════════════
#                    NOUVELLES FONCTIONS V2.0 - COMPARAISONS
# ═══════════════════════════════════════════════════════════════════════════

def benchmark_cesar_vs_aes():
    """
    Compare le temps de chiffrement César vs AES-GCM
    Démontre la différence de performance
    """
    print("\n" + "=" * 80)
    print("⚡ BENCHMARK: CÉSAR vs AES-256-GCM")
    print("=" * 80)
    
    message = "BONJOUR LA SECURITE EST IMPORTANTE" * 10  # Message répété
    
    print(f"\n📝 Message de test:")
    print(f"   Longueur: {len(message)} caractères")
    print(f"   Contenu: {message[:50]}...")
    
    # César (simulation simple)
    print(f"\n🔄 CÉSAR:")
    print(f"   Algorithme: Substitution (k=3)")
    
    start = time.time()
    # Chiffrement César simple
    cesar_chiffre = ''.join(
        chr((ord(c) - ord('A') + 3) % 26 + ord('A')) if c.isalpha() else c
        for c in message
    )
    temps_cesar = time.time() - start
    
    print(f"   ⏱️  Temps de chiffrement: {temps_cesar*1000:.4f} ms")
    print(f"   🔑 Clés possibles: 26")
    print(f"   💥 Temps force brute: < 1 ms (TRIVIAL!)")
    
    # AES-GCM
    print(f"\n🔒 AES-256-GCM:")
    print(f"   Algorithme: AES-256 + Galois Counter Mode")
    
    cle = generer_cle_aleatoire()
    
    start = time.time()
    donnees = chiffrer_aes_gcm(message, cle)
    temps_aes = time.time() - start
    
    print(f"   ⏱️  Temps de chiffrement: {temps_aes*1000:.4f} ms")
    print(f"   🔑 Clés possibles: 2^256 ≈ 10^77")
    print(f"   💪 Temps force brute: > Âge de l'univers (IMPOSSIBLE!)")
    
    # Comparaison
    print("\n" + "=" * 80)
    print("📊 COMPARAISON")
    print("=" * 80)
    
    rapport = temps_cesar / temps_aes if temps_aes > 0 else 0
    
    print(f"\n⚡ Performance:")
    print(f"   César:   {temps_cesar*1000:.4f} ms")
    print(f"   AES-GCM: {temps_aes*1000:.4f} ms")
    
    if rapport > 1:
        print(f"   → AES est {rapport:.1f}x plus RAPIDE!")
    else:
        print(f"   → César est {1/rapport:.1f}x plus rapide")
        print(f"      (Mais totalement INSÉCURISÉ!)")
    
    print(f"\n🔐 Sécurité:")
    print(f"   César:   ❌ Cassé en < 1 ms")
    print(f"   AES-GCM: ✅ Incassable (force brute impossible)")
    
    print(f"\n📏 Taille des données:")
    print(f"   Message original:  {len(message)} octets")
    print(f"   César chiffré:     {len(cesar_chiffre)} octets (identique)")
    print(f"   AES-GCM chiffré:   {len(donnees['chiffre'])} octets (+16 pour tag)")
    print(f"   AES-GCM nonce:     {len(donnees['nonce'])} octets")
    
    print(f"\n💡 CONCLUSION:")
    print(f"   ✅ AES-GCM est aussi rapide (voire plus rapide)")
    print(f"   ✅ AES-GCM est INFINIMENT plus sécurisé")
    print(f"   ✅ AES-GCM offre authentification (tag)")
    print(f"   → Aucune raison d'utiliser César!")
    
    print("\n" + "=" * 80)


def demo_ecb_vs_gcm():
    """
    Démontre la différence entre ECB et GCM
    (sans image, juste avec texte)
    """
    print("\n" + "=" * 80)
    print("🎯 DÉMONSTRATION: ECB vs GCM (TEXTE)")
    print("=" * 80)
    
    # Message avec répétitions
    message = "HELLO " * 20  # Répétitions visibles
    
    print(f"\n📝 Message de test (avec répétitions):")
    print(f"   {message}")
    print(f"   Longueur: {len(message)} caractères")
    
    cle = generer_cle_aleatoire()
    
    # Simulation ECB (même bloc → même chiffré)
    print(f"\n❌ MODE ECB (DANGEREUX):")
    print(f"   Principe: Chaque bloc chiffré indépendamment")
    
    # Avec ECB, "HELLO " chiffré serait toujours identique
    print(f"\n   Si on chiffrait avec ECB:")
    print(f"   HELLO → [Bloc A]")
    print(f"   HELLO → [Bloc A]  ← Identique!")
    print(f"   HELLO → [Bloc A]  ← Identique!")
    print(f"   ...")
    print(f"\n   💀 Problème: Les répétitions sont VISIBLES")
    print(f"   💀 Attaquant peut déduire la structure")
    
    # GCM
    print(f"\n✅ MODE GCM (SÉCURISÉ):")
    print(f"   Principe: Chaque bloc dépend du nonce unique")
    
    # Chiffrer 3 fois le même message
    chiffres = []
    for i in range(3):
        donnees = chiffrer_aes_gcm(message, cle)
        chiffres.append(base64.b64encode(donnees['chiffre'])[:32].decode('utf-8'))
    
    print(f"\n   Chiffrement #1: {chiffres[0]}...")
    print(f"   Chiffrement #2: {chiffres[1]}...")
    print(f"   Chiffrement #3: {chiffres[2]}...")
    
    print(f"\n   ✅ Chaque chiffrement est DIFFÉRENT")
    print(f"   ✅ Impossible de détecter les répétitions")
    print(f"   ✅ Protection contre l'analyse")
    
    print("\n" + "=" * 80)
    print("📊 TABLEAU RÉCAPITULATIF")
    print("=" * 80)
    print(f"""
╔════════════════════╦═══════════════╦═══════════════╗
║     CRITÈRE        ║   AES-ECB     ║   AES-GCM     ║
╠════════════════════╬═══════════════╬═══════════════╣
║ Même→Même          ║ ✅ Oui (mal)  ║ ❌ Non (bien) ║
║ Préserve motifs    ║ ✅ Oui (mal)  ║ ❌ Non (bien) ║
║ Authentification   ║ ❌ Non        ║ ✅ Oui (tag)  ║
║ Détection altérat. ║ ❌ Non        ║ ✅ Oui        ║
║ Usage production   ║ ❌ INTERDIT   ║ ✅ RECOMMANDÉ ║
╚════════════════════╩═══════════════╩═══════════════╝
    """)
    
    print("💡 CONCLUSION:")
    print("   → ECB préserve les motifs (comme le pingouin du TP3)")
    print("   → GCM détruit les motifs (sécurisé)")
    print("\n" + "=" * 80)


# ═══════════════════════════════════════════════════════════════════════════
#                    MODES INTERACTIFS V2.0
# ═══════════════════════════════════════════════════════════════════════════

def mode_chiffrer_interactif():
    """Mode interactif pour chiffrer un message"""
    print("\n" + "=" * 80)
    print("🔒 MODE INTERACTIF: CHIFFRER UN MESSAGE")
    print("=" * 80)
    
    # Saisir le message
    print(f"\n📝 Entrez votre message à chiffrer:")
    message = input("   > ")
    
    if not message:
        print("❌ Message vide!")
        return
    
    # Choix: clé aléatoire ou mot de passe
    print(f"\n🔑 Choix de la clé:")
    print(f"   1. Générer une clé aléatoire (256 bits)")
    print(f"   2. Utiliser un mot de passe (PBKDF2)")
    
    choix = input("\n👉 Votre choix (1 ou 2): ").strip()
    
    if choix == "1":
        cle = generer_cle_aleatoire()
        print(f"\n✅ Clé générée:")
        print(f"   {base64.b64encode(cle).decode('utf-8')}")
        salt = None
        
    elif choix == "2":
        mot_de_passe = input("\n🔐 Entrez votre mot de passe: ")
        print(f"\n⚙️  Dérivation de clé (600,000 itérations)...")
        cle, salt = deriver_cle_depuis_mot_de_passe(mot_de_passe)
        print(f"✅ Clé dérivée avec succès")
        print(f"   Salt: {base64.b64encode(salt).decode('utf-8')}")
    else:
        print("❌ Choix invalide!")
        return
    
    # AAD optionnel
    aad = input("\n📋 Données additionnelles (optionnel, appuyez sur ENTRÉE pour passer): ").strip()
    aad = aad if aad else None
    
    # Chiffrer
    print(f"\n🔒 Chiffrement en cours...")
    donnees = chiffrer_aes_gcm(message, cle, aad)
    
    print("\n" + "=" * 80)
    print("✅ MESSAGE CHIFFRÉ")
    print("=" * 80)
    
    print(f"\n🔒 Chiffré (Base64):")
    print(f"   {base64.b64encode(donnees['chiffre']).decode('utf-8')}")
    
    print(f"\n🎲 Nonce:")
    print(f"   {base64.b64encode(donnees['nonce']).decode('utf-8')}")
    
    if aad:
        print(f"\n📋 AAD:")
        print(f"   {aad}")
    
    # Sauvegarder?
    sauver = input("\n💾 Sauvegarder ce message? (o/n): ").strip().lower()
    
    if sauver == 'o':
        nom = input("   Nom du message: ").strip()
        fichier = sauvegarder_message_chiffre(nom, donnees, cle)
        print(f"✅ Sauvegardé: {fichier}")
        
        if salt:
            print(f"\n⚠️  IMPORTANT: Sauvegardez aussi le salt!")
            print(f"   Salt: {base64.b64encode(salt).decode('utf-8')}")
    
    print("\n" + "=" * 80)


def mode_dechiffrer_interactif():
    """Mode interactif pour déchiffrer un message"""
    print("\n" + "=" * 80)
    print("🔓 MODE INTERACTIF: DÉCHIFFRER UN MESSAGE")
    print("=" * 80)
    
    # Choix: nouveau ou chargé
    print(f"\n📂 Source:")
    print(f"   1. Entrer les données manuellement")
    print(f"   2. Charger depuis un fichier sauvegardé")
    
    choix = input("\n👉 Votre choix (1 ou 2): ").strip()
    
    if choix == "2":
        # Lister les messages
        messages = lister_messages_sauvegardes()
        
        if not messages:
            print("❌ Aucun message sauvegardé!")
            return
        
        print(f"\n📋 Messages disponibles:")
        for i, msg in enumerate(messages, 1):
            print(f"   {i}. {msg['nom']} ({msg['date']})")
        
        idx = int(input(f"\n👉 Choisir (1-{len(messages)}): ")) - 1
        
        if 0 <= idx < len(messages):
            fichier = SAVE_DIR / messages[idx]['fichier']
            donnees, cle = charger_message_chiffre(fichier)
            print(f"✅ Message chargé!")
        else:
            print("❌ Choix invalide!")
            return
    
    elif choix == "1":
        # Saisie manuelle
        chiffre_b64 = input("\n🔒 Message chiffré (Base64): ").strip()
        nonce_b64 = input("🎲 Nonce (Base64): ").strip()
        aad = input("📋 AAD (optionnel): ").strip()
        
        donnees = {
            'chiffre': base64.b64decode(chiffre_b64),
            'nonce': base64.b64decode(nonce_b64),
            'aad': aad if aad else None
        }
        
        # Clé
        print(f"\n🔑 Clé:")
        print(f"   1. Clé directe (Base64)")
        print(f"   2. Mot de passe (+ salt)")
        
        choix_cle = input("\n👉 Votre choix (1 ou 2): ").strip()
        
        if choix_cle == "1":
            cle_b64 = input("🔑 Clé (Base64): ").strip()
            cle = base64.b64decode(cle_b64)
        elif choix_cle == "2":
            mot_de_passe = input("🔐 Mot de passe: ")
            salt_b64 = input("🧂 Salt (Base64): ").strip()
            salt = base64.b64decode(salt_b64)
            
            print(f"\n⚙️  Dérivation de clé...")
            cle, _ = deriver_cle_depuis_mot_de_passe(mot_de_passe, salt)
        else:
            print("❌ Choix invalide!")
            return
    else:
        print("❌ Choix invalide!")
        return
    
    # Déchiffrer
    print(f"\n🔓 Déchiffrement en cours...")
    
    try:
        message = dechiffrer_aes_gcm(donnees, cle)
        
        print("\n" + "=" * 80)
        print("✅ MESSAGE DÉCHIFFRÉ")
        print("=" * 80)
        print(f"\n📄 {message}")
        print("\n" + "=" * 80)
        
    except InvalidTag:
        print("\n❌ ÉCHEC: Message altéré ou clé incorrecte!")
    except Exception as e:
        print(f"\n❌ ERREUR: {e}")


def mode_chiffrer_fichier():
    """Mode pour chiffrer un fichier"""
    print("\n" + "=" * 80)
    print("📁 CHIFFREMENT DE FICHIER")
    print("=" * 80)
    
    fichier = input("\n📄 Chemin du fichier à chiffrer: ").strip()
    
    if not os.path.exists(fichier):
        print(f"❌ Fichier introuvable: {fichier}")
        return
    
    # Clé
    print(f"\n🔑 Générer une clé aléatoire? (o/n): ")
    choix = input("   > ").strip().lower()
    
    if choix == 'o':
        cle = generer_cle_aleatoire()
        nom_cle = input("💾 Nom pour sauvegarder la clé: ").strip()
        fichier_cle = sauvegarder_cle(nom_cle, cle)
        print(f"✅ Clé sauvegardée: {fichier_cle}")
    else:
        cle_b64 = input("🔑 Clé (Base64): ").strip()
        cle = base64.b64decode(cle_b64)
    
    # Chiffrer
    print(f"\n🔒 Chiffrement en cours...")
    
    try:
        fichier_chiffre = chiffrer_fichier(fichier, cle)
        
        print(f"\n✅ FICHIER CHIFFRÉ:")
        print(f"   Original: {fichier}")
        print(f"   Chiffré:  {fichier_chiffre}")
        print(f"   Taille:   {os.path.getsize(fichier_chiffre)} octets")
        
    except Exception as e:
        print(f"❌ ERREUR: {e}")


def mode_dechiffrer_fichier():
    """Mode pour déchiffrer un fichier"""
    print("\n" + "=" * 80)
    print("🔓 DÉCHIFFREMENT DE FICHIER")
    print("=" * 80)
    
    fichier = input("\n📄 Chemin du fichier chiffré: ").strip()
    
    if not os.path.exists(fichier):
        print(f"❌ Fichier introuvable: {fichier}")
        return
    
    # Clé
    print(f"\n🔑 Source de la clé:")
    print(f"   1. Charger depuis fichier")
    print(f"   2. Entrer manuellement (Base64)")
    
    choix = input("\n👉 Votre choix (1 ou 2): ").strip()
    
    if choix == "1":
        cles = lister_cles()
        
        if not cles:
            print("❌ Aucune clé sauvegardée!")
            return
        
        print(f"\n🔑 Clés disponibles:")
        for i, c in enumerate(cles, 1):
            print(f"   {i}. {c['nom']} ({c['taille']} bits)")
        
        idx = int(input(f"\n👉 Choisir (1-{len(cles)}): ")) - 1
        
        if 0 <= idx < len(cles):
            cle = charger_cle(cles[idx]['nom'])
        else:
            print("❌ Choix invalide!")
            return
    elif choix == "2":
        cle_b64 = input("🔑 Clé (Base64): ").strip()
        cle = base64.b64decode(cle_b64)
    else:
        print("❌ Choix invalide!")
        return
    
    # Déchiffrer
    print(f"\n🔓 Déchiffrement en cours...")
    
    try:
        fichier_dechiffre = dechiffrer_fichier(fichier, cle)
        
        print(f"\n✅ FICHIER DÉCHIFFRÉ:")
        print(f"   Chiffré:   {fichier}")
        print(f"   Déchiffré: {fichier_dechiffre}")
        print(f"   Taille:    {os.path.getsize(fichier_dechiffre)} octets")
        
    except InvalidTag:
        print("❌ ÉCHEC: Fichier altéré ou clé incorrecte!")
    except Exception as e:
        print(f"❌ ERREUR: {e}")


# ═══════════════════════════════════════════════════════════════════════════
#                    DÉMONSTRATIONS V1.0 (CONSERVÉES)
# ═══════════════════════════════════════════════════════════════════════════

def demo_chiffrement_simple():
    """Démonstration basique - Version V1.0"""
    print("\n" + "=" * 80)
    print("🎯 DÉMO 1: CHIFFREMENT/DÉCHIFFREMENT BASIQUE")
    print("=" * 80)
    
    message = "La sécurité est importante en 2026!"
    print(f"\n📝 Message: {message}")
    
    cle = generer_cle_aleatoire()
    print(f"\n🔑 Clé (hex): {cle.hex()[:32]}...")
    
    print(f"\n🔒 Chiffrement...")
    donnees = chiffrer_aes_gcm(message, cle)
    
    print(f"   Chiffré: {base64.b64encode(donnees['chiffre']).decode('utf-8')[:32]}...")
    print(f"   Nonce:   {donnees['nonce'].hex()}")
    
    print(f"\n🔓 Déchiffrement...")
    message_clair = dechiffrer_aes_gcm(donnees, cle)
    
    print(f"\n✅ Résultat: {message_clair}")
    print(f"   Identique? {'✅ OUI' if message == message_clair else '❌ NON'}")
    print("\n" + "=" * 80)


def demo_mot_de_passe():
    """Démo PBKDF2 - Version V1.0"""
    print("\n" + "=" * 80)
    print("🎯 DÉMO 2: CHIFFREMENT AVEC MOT DE PASSE")
    print("=" * 80)
    
    message = "Compte: FR76 1234 5678 9012"
    mot_de_passe = "MonMotDePasse2026!"
    
    print(f"\n📝 Message: {message}")
    print(f"🔐 Mot de passe: {mot_de_passe}")
    
    print(f"\n⚙️  Dérivation PBKDF2 (600,000 itérations)...")
    cle, salt = deriver_cle_depuis_mot_de_passe(mot_de_passe)
    
    print(f"✅ Clé dérivée")
    print(f"   Salt: {salt.hex()}")
    
    print(f"\n🔒 Chiffrement...")
    donnees = chiffrer_aes_gcm(message, cle, "user:farah")
    
    print(f"   AAD: {donnees['aad']}")
    
    print(f"\n🔓 Déchiffrement...")
    cle2, _ = deriver_cle_depuis_mot_de_passe(mot_de_passe, salt)
    message_clair = dechiffrer_aes_gcm(donnees, cle2)
    
    print(f"\n✅ Résultat: {message_clair}")
    print("\n" + "=" * 80)


def demo_detection_alteration():
    """Démo détection - Version V1.0"""
    print("\n" + "=" * 80)
    print("🎯 DÉMO 3: DÉTECTION D'ALTÉRATION")
    print("=" * 80)
    
    message = "Transférer 100€ à Alice"
    print(f"\n📝 Message: {message}")
    
    cle = generer_cle_aleatoire()
    donnees = chiffrer_aes_gcm(message, cle)
    
    print(f"\n😈 Modification d'un octet...")
    donnees_alt = donnees.copy()
    chiffre_mod = bytearray(donnees['chiffre'])
    chiffre_mod[0] ^= 0xFF
    donnees_alt['chiffre'] = bytes(chiffre_mod)
    
    print(f"\n🔓 Tentative de déchiffrement...")
    
    try:
        dechiffrer_aes_gcm(donnees_alt, cle)
        print(f"❌ PROBLÈME: Altération non détectée!")
    except InvalidTag:
        print(f"✅ SUCCÈS: Altération détectée!")
        print(f"   Le tag ne correspond pas")
        print(f"   Protection assurée!")
    
    print("\n" + "=" * 80)


def demo_unicite_nonce():
    """Démo nonce unique - Version V1.0"""
    print("\n" + "=" * 80)
    print("🎯 DÉMO 4: UNICITÉ DU NONCE")
    print("=" * 80)
    
    message = "Message confidentiel"
    cle = generer_cle_aleatoire()
    
    print(f"\n📝 Message: {message}")
    print(f"🔑 Même clé pour 2 chiffrements")
    
    donnees1 = chiffrer_aes_gcm(message, cle)
    donnees2 = chiffrer_aes_gcm(message, cle)
    
    print(f"\n🔒 Chiffrement #1:")
    print(f"   Nonce:   {donnees1['nonce'].hex()}")
    print(f"   Chiffré: {donnees1['chiffre'].hex()[:32]}...")
    
    print(f"\n🔒 Chiffrement #2:")
    print(f"   Nonce:   {donnees2['nonce'].hex()}")
    print(f"   Chiffré: {donnees2['chiffre'].hex()[:32]}...")
    
    print(f"\n📊 Comparaison:")
    print(f"   Nonces identiques? {'OUI ❌' if donnees1['nonce'] == donnees2['nonce'] else 'NON ✅'}")
    print(f"   Chiffrés identiques? {'OUI ❌' if donnees1['chiffre'] == donnees2['chiffre'] else 'NON ✅'}")
    
    print(f"\n💡 → Même message → Chiffrés DIFFÉRENTS!")
    print("\n" + "=" * 80)


# ═══════════════════════════════════════════════════════════════════════════
#                    INTERFACE UTILISATEUR V2.0
# ═══════════════════════════════════════════════════════════════════════════

def afficher_banniere():
    """Bannière V2.0"""
    print("\n" + "=" * 80)
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║      🔐 CRYPTOGRAPHIE MODERNE - VERSION 2.0 🔐               ║
    ║                                                               ║
    ║      TP4 - Implémentation Complète                            ║
    ║      Bibliothèque: cryptography                               ║
    ║                                                               ║                                     ║
    ║      • Modes interactifs                                      ║
    ║      • Chiffrement de fichiers                                ║
    ║      • Sauvegarde/chargement                                  ║
    ║      • Comparaisons temps réel                                ║
    ║                                                               ║
    ║      ISGA Marrakech | Farah El Alem                           ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    print("=" * 80)


def afficher_menu():
    """Menu V2.0"""
    print("\n" + "=" * 80)
    print("📋 MENU PRINCIPAL")
    print("=" * 80)
    print("""
📚 DÉMONSTRATIONS AUTOMATIQUES:
1️⃣  - Démo 1: Chiffrement/Déchiffrement basique
2️⃣  - Démo 2: PBKDF2 (mot de passe)
3️⃣  - Démo 3: Détection altération
4️⃣  - Démo 4: Unicité du nonce
5️⃣  - Toutes les démos

🎮 MODES INTERACTIFS:
6️⃣  - Chiffrer un message (vous choisissez)
7️⃣  - Déchiffrer un message
8️⃣  - Chiffrer un fichier
9️⃣  - Déchiffrer un fichier

📊 COMPARAISONS ET BENCHMARKS:
🔟 - Benchmark César vs AES-GCM
1️⃣1️⃣ - Comparaison ECB vs GCM

💾 GESTION:
1️⃣2️⃣ - Lister messages sauvegardés
1️⃣3️⃣ - Lister clés sauvegardées

0️⃣  - Quitter
    """)
    print("=" * 80)


def main():
    """Fonction principale"""
    
    afficher_banniere()
    
    while True:
        afficher_menu()
        
        choix = input("👉 Votre choix: ").strip()
        
        try:
            if choix == "1":
                demo_chiffrement_simple()
            elif choix == "2":
                demo_mot_de_passe()
            elif choix == "3":
                demo_detection_alteration()
            elif choix == "4":
                demo_unicite_nonce()
            elif choix == "5":
                demo_chiffrement_simple()
                input("\n⏎ ENTRÉE pour continuer...")
                demo_mot_de_passe()
                input("\n⏎ ENTRÉE pour continuer...")
                demo_detection_alteration()
                input("\n⏎ ENTRÉE pour continuer...")
                demo_unicite_nonce()
            elif choix == "6":
                mode_chiffrer_interactif()
            elif choix == "7":
                mode_dechiffrer_interactif()
            elif choix == "8":
                mode_chiffrer_fichier()
            elif choix == "9":
                mode_dechiffrer_fichier()
            elif choix == "10":
                benchmark_cesar_vs_aes()
            elif choix == "11":
                demo_ecb_vs_gcm()
            elif choix == "12":
                messages = lister_messages_sauvegardes()
                print(f"\n📋 Messages sauvegardés ({len(messages)}):")
                for msg in messages:
                    print(f"   • {msg['nom']} - {msg['date']}")
            elif choix == "13":
                cles = lister_cles()
                print(f"\n🔑 Clés sauvegardées ({len(cles)}):")
                for cle in cles:
                    print(f"   • {cle['nom']} ({cle['taille']} bits) - {cle['date']}")
            elif choix == "0":
                print("\n" + "=" * 80)
                print("👋 Au revoir!")
                print("\n💡 Points clés:")
                print("   ✅ Toujours utiliser des bibliothèques éprouvées")
                print("   ✅ AES-GCM pour chiffrement authentifié")
                print("   ❌ Ne JAMAIS créer son propre algorithme")
                print("\n" + "=" * 80 + "\n")
                break
            else:
                print("\n❌ Choix invalide!")
            
            input("\n⏎ Appuyez sur ENTRÉE pour continuer...")
            
        except KeyboardInterrupt:
            print("\n\n⚠️  Interrompu")
            break
        except Exception as e:
            print(f"\n❌ ERREUR: {e}")
            input("\n⏎ Appuyez sur ENTRÉE pour continuer...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Programme interrompu.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Erreur fatale: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
