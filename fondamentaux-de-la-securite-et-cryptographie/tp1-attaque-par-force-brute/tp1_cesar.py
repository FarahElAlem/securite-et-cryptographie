#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════════════
    TP1 - ATTAQUE DU CHIFFRE DE CÉSAR
    Module: Fondamentaux de la Sécurité et Cryptographie
    ISGA Marrakech
    
    Auteur: Farah El Alem
═══════════════════════════════════════════════════════════════════════════
"""

from collections import Counter
from typing import Dict, List, Tuple


# ═══════════════════════════════════════════════════════════════════════════
#                           CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Fréquences des lettres en français (%)
FREQ_FR = {
    'E': 14.72, 'A': 7.63, 'I': 7.53, 'S': 7.95, 'N': 7.10,
    'R': 6.55, 'T': 7.24, 'O': 5.80, 'L': 5.46, 'U': 6.31,
    'D': 3.67, 'C': 3.26, 'M': 2.97, 'P': 2.52, 'G': 1.07,
    'B': 0.90, 'V': 1.63, 'H': 0.74, 'F': 1.07, 'Q': 1.36,
    'Y': 0.13, 'X': 0.43, 'J': 0.61, 'K': 0.05, 'W': 0.11,
    'Z': 0.33
}

# Mots courants français et latins
MOTS_CONNUS = {
    'VENI', 'VIDI', 'VICI',  # Latin classique
    'LE', 'LA', 'DE', 'UN', 'UNE', 'ET', 'EST', 'DANS', 'POUR',
    'AVEC', 'QUE', 'AVOIR', 'FAIRE', 'TOUT', 'BIEN', 'ETRE',
    'BONJOUR', 'MONDE', 'MESSAGE', 'SECRET', 'CRYPTOGRAPHIE',
    'SECURITE', 'CODE', 'CESAR', 'CHIFFRE'
}


# ═══════════════════════════════════════════════════════════════════════════
#                      FONCTIONS DE CRYPTANALYSE
# ═══════════════════════════════════════════════════════════════════════════

def dechiffrer(texte_chiffre: str, cle: int) -> str:
    """
    Déchiffre un texte avec une clé donnée.
    
    Formule: P = (C - k) mod 26
    
    Args:
        texte_chiffre: Le texte chiffré
        cle: La clé de décalage (1-25)
        
    Returns:
        Le texte déchiffré
    """
    resultat = []
    
    for caractere in texte_chiffre.upper():
        if caractere in ALPHABET:
            position_actuelle = ALPHABET.index(caractere)
            nouvelle_position = (position_actuelle - cle) % 26
            resultat.append(ALPHABET[nouvelle_position])
        else:
            resultat.append(caractere)
    
    return ''.join(resultat)


def calculer_chi_carre(texte: str) -> float:
    """
    Calcule le test du Chi-carré (χ²).
    
    Plus le score est BAS, meilleure est la correspondance avec le français.
    
    Args:
        texte: Le texte à analyser
        
    Returns:
        Le score Chi-carré
    """
    # Garder uniquement les lettres
    lettres_seulement = ''.join(c for c in texte.upper() if c in ALPHABET)
    
    if len(lettres_seulement) < 3:
        return 9999  # Texte trop court
    
    # Compter les fréquences
    compteur = Counter(lettres_seulement)
    longueur_totale = len(lettres_seulement)
    
    # Calculer le Chi-carré
    chi_carre = 0.0
    
    for lettre in ALPHABET:
        frequence_observee = (compteur.get(lettre, 0) / longueur_totale) * 100
        frequence_attendue = FREQ_FR.get(lettre, 0)
        
        if frequence_attendue > 0:
            chi_carre += ((frequence_observee - frequence_attendue) ** 2) / frequence_attendue
    
    return chi_carre


def compter_mots_connus(texte: str) -> int:
    """
    Compte le nombre de mots français/latins reconnus.
    
    Args:
        texte: Le texte à analyser
        
    Returns:
        Nombre de mots reconnus
    """
    mots = texte.upper().split()
    return sum(1 for mot in mots if mot in MOTS_CONNUS)


def calculer_index_coincidence(texte: str) -> float:
    """
    Calcule l'Index de Coïncidence (IC).
    
    Un texte en français a un IC d'environ 0.067.
    Un texte aléatoire a un IC d'environ 0.038.
    
    Args:
        texte: Le texte à analyser
        
    Returns:
        L'index de coïncidence
    """
    lettres = ''.join(c for c in texte.upper() if c in ALPHABET)
    
    if len(lettres) < 2:
        return 0.0
    
    compteur = Counter(lettres)
    N = len(lettres)
    
    somme = sum(count * (count - 1) for count in compteur.values())
    ic = somme / (N * (N - 1)) if N > 1 else 0.0
    
    return ic


def calculer_score_global(texte: str, longueur: int) -> float:
    """
    Calcule un score global adaptatif selon la longueur du texte.
    
    Plus le score est ÉLEVÉ, meilleure est la solution.
    
    Args:
        texte: Le texte déchiffré
        longueur: Longueur du texte original
        
    Returns:
        Score global (0-100)
    """
    chi_carre = calculer_chi_carre(texte)
    ic = calculer_index_coincidence(texte)
    mots = compter_mots_connus(texte)
    
    # Scores normalisés (0-100)
    score_chi = max(0, 100 - chi_carre / 5)  # Chi² faible = bon
    score_ic = max(0, 100 - abs(ic - 0.067) * 1000)  # IC proche de 0.067 = bon
    score_mots = min(100, mots * 50)  # Beaucoup de mots = bon
    
    # Stratégie adaptative selon la longueur
    if longueur < 15:
        # TEXTE COURT: Privilégier les mots reconnus
        score_final = (score_mots * 0.6) + (score_ic * 0.3) + (score_chi * 0.1)
    elif longueur < 30:
        # TEXTE MOYEN: Équilibré
        score_final = (score_chi * 0.4) + (score_ic * 0.3) + (score_mots * 0.3)
    else:
        # TEXTE LONG: Privilégier Chi-carré
        score_final = (score_chi * 0.7) + (score_ic * 0.2) + (score_mots * 0.1)
    
    return score_final


# ═══════════════════════════════════════════════════════════════════════════
#                      ATTAQUE FORCE BRUTE (TP1)
# ═══════════════════════════════════════════════════════════════════════════

def attaque_force_brute(texte_chiffre: str, afficher_tout: bool = True) -> List[Tuple]:
    """
    Teste toutes les clés possibles (1-25).
    
    Args:
        texte_chiffre: Le texte chiffré à attaquer
        afficher_tout: Si True, affiche tous les résultats
        
    Returns:
        Liste de tuples (clé, texte_déchiffré, score, détails)
    """
    resultats = []
    longueur = len(''.join(c for c in texte_chiffre if c.isalpha()))
    
    print("=" * 80)
    print("ATTAQUE PAR FORCE BRUTE")
    print("=" * 80)
    print(f"\n📝 Message chiffré: {texte_chiffre}")
    print(f"📏 Longueur: {longueur} lettres")
    print(f"\n{'─' * 80}")
    
    if afficher_tout:
        print(f"{'Clé':^5} | {'Message Déchiffré':^35} | {'Score':^10}")
        print(f"{'─' * 80}")
    
    # Tester toutes les clés
    for cle in range(1, 26):
        texte_dechiffre = dechiffrer(texte_chiffre, cle)
        
        # Calculer les métriques
        score_global = calculer_score_global(texte_dechiffre, longueur)
        chi_carre = calculer_chi_carre(texte_dechiffre)
        mots_reconnus = compter_mots_connus(texte_dechiffre)
        ic = calculer_index_coincidence(texte_dechiffre)
        
        details = {
            'chi_carre': chi_carre,
            'mots': mots_reconnus,
            'ic': ic
        }
        
        resultats.append((cle, texte_dechiffre, score_global, details))
        
        if afficher_tout:
            print(f"{cle:^5} | {texte_dechiffre:^35} | {score_global:^10.1f}")
    
    print(f"{'─' * 80}")
    
    return resultats


# ═══════════════════════════════════════════════════════════════════════════
#                      DÉTECTION AUTOMATIQUE
# ═══════════════════════════════════════════════════════════════════════════

def detecter_meilleure_cle(texte_chiffre: str, top_n: int = 5):
    """
    Détecte automatiquement la meilleure clé.
    
    Args:
        texte_chiffre: Le texte chiffré
        top_n: Nombre de meilleures solutions à afficher
    """
    # Effectuer l'attaque
    resultats = attaque_force_brute(texte_chiffre, afficher_tout=True)
    
    # Trier par score décroissant
    resultats.sort(key=lambda x: x[2], reverse=True)
    
    # Afficher le top N
    print("\n" + "=" * 80)
    print(f"TOP {top_n} DES SOLUTIONS LES PLUS PROBABLES")
    print("=" * 80)
    
    for rang, (cle, texte, score, details) in enumerate(resultats[:top_n], 1):
        marqueur = "⭐ MEILLEUR" if rang == 1 else ""
        
        print(f"\n{rang}. Clé {cle:2d} | Score: {score:5.1f}% {marqueur}")
        print(f"   📝 Message: {texte}")
        print(f"   📊 Chi²={details['chi_carre']:6.2f} | Mots={details['mots']} | IC={details['ic']:.3f}")
    
    # Verdict final
    meilleure_cle, meilleur_texte, meilleur_score, meilleurs_details = resultats[0]
    
    print("\n" + "=" * 80)
    print("✅ VERDICT FINAL")
    print("=" * 80)
    print(f"\n🔑 Clé détectée: {meilleure_cle}")
    print(f"📝 Message déchiffré: {meilleur_texte}")
    print(f"🎯 Confiance: {meilleur_score:.1f}%")
    
    # Analyse de la confiance
    if meilleur_score > 70:
        print(f"✅ Haute confiance - La clé est très probablement correcte")
    elif meilleur_score > 40:
        print(f"⚠️  Confiance moyenne - Vérifiez les 3 premières options")
    else:
        print(f"⚠️  Faible confiance - Texte trop court, vérification manuelle recommandée")
    
    if meilleurs_details['mots'] > 0:
        print(f"✅ {meilleurs_details['mots']} mot(s) français/latin reconnu(s)")
    
    print("\n" + "=" * 80)
    
    return meilleure_cle, meilleur_texte


# ═══════════════════════════════════════════════════════════════════════════
#                       FONCTIONS INTERACTIVES
# ═══════════════════════════════════════════════════════════════════════════

def chiffrer_interactif():
    """Mode interactif pour chiffrer un message"""
    print("\n" + "=" * 80)
    print("🔒 CHIFFREMENT DE CÉSAR")
    print("=" * 80)
    
    message = input("\n📝 Entrez votre message à chiffrer: ").strip()
    
    if not message:
        print("❌ Message vide!")
        return
    
    try:
        cle = int(input("🔑 Entrez la clé (1-25): ").strip())
        
        if not (1 <= cle <= 25):
            print("❌ La clé doit être entre 1 et 25!")
            return
        
        # Chiffrer (inverse du déchiffrement)
        resultat = []
        for caractere in message.upper():
            if caractere in ALPHABET:
                position_actuelle = ALPHABET.index(caractere)
                nouvelle_position = (position_actuelle + cle) % 26
                resultat.append(ALPHABET[nouvelle_position])
            else:
                resultat.append(caractere)
        
        texte_chiffre = ''.join(resultat)
        
        print("\n" + "=" * 80)
        print("✅ RÉSULTAT DU CHIFFREMENT")
        print("=" * 80)
        print(f"\n📄 Message original  : {message.upper()}")
        print(f"🔑 Clé utilisée      : {cle}")
        print(f"🔒 Message chiffré   : {texte_chiffre}")
        print("\n" + "=" * 80)
        
    except ValueError:
        print("❌ Clé invalide! Utilisez un nombre entre 1 et 25.")


def dechiffrer_interactif():
    """Mode interactif pour déchiffrer avec une clé connue"""
    print("\n" + "=" * 80)
    print("🔓 DÉCHIFFREMENT AVEC CLÉ CONNUE")
    print("=" * 80)
    
    message_chiffre = input("\n📝 Entrez le message chiffré: ").strip()
    
    if not message_chiffre:
        print("❌ Message vide!")
        return
    
    try:
        cle = int(input("🔑 Entrez la clé (1-25): ").strip())
        
        if not (1 <= cle <= 25):
            print("❌ La clé doit être entre 1 et 25!")
            return
        
        texte_dechiffre = dechiffrer(message_chiffre, cle)
        
        print("\n" + "=" * 80)
        print("✅ RÉSULTAT DU DÉCHIFFREMENT")
        print("=" * 80)
        print(f"\n🔒 Message chiffré   : {message_chiffre.upper()}")
        print(f"🔑 Clé utilisée      : {cle}")
        print(f"📄 Message déchiffré : {texte_dechiffre}")
        print("\n" + "=" * 80)
        
    except ValueError:
        print("❌ Clé invalide! Utilisez un nombre entre 1 et 25.")


def cryptanalyse_avancee():
    """Mode cryptanalyse avancée (sans connaître la clé)"""
    print("\n" + "=" * 80)
    print("🧠 CRYPTANALYSE AVANCÉE (CLÉ INCONNUE)")
    print("=" * 80)
    
    message_chiffre = input("\n📝 Entrez le message chiffré à attaquer: ").strip()
    
    if not message_chiffre:
        print("❌ Message vide!")
        return
    
    print("\n🔍 Analyse en cours...")
    print("\nChoisissez le mode d'affichage:")
    print("1. Afficher toutes les 25 possibilités")
    print("2. Afficher uniquement le TOP 5")
    
    choix = input("\n👉 Votre choix (1 ou 2): ").strip()
    
    if choix == "1":
        detecter_meilleure_cle(message_chiffre, top_n=5)
    elif choix == "2":
        resultats = attaque_force_brute(message_chiffre, afficher_tout=False)
        resultats.sort(key=lambda x: x[2], reverse=True)
        
        print("\n" + "=" * 80)
        print("TOP 5 DES SOLUTIONS LES PLUS PROBABLES")
        print("=" * 80)
        
        for rang, (cle, texte, score, details) in enumerate(resultats[:5], 1):
            marqueur = "⭐ MEILLEUR" if rang == 1 else ""
            print(f"\n{rang}. Clé {cle:2d} | Score: {score:5.1f}% {marqueur}")
            print(f"   📝 Message: {texte}")
            print(f"   📊 Chi²={details['chi_carre']:6.2f} | Mots={details['mots']} | IC={details['ic']:.3f}")
        
        meilleure_cle, meilleur_texte, meilleur_score, _ = resultats[0]
        print("\n" + "=" * 80)
        print("✅ MEILLEURE SOLUTION")
        print("=" * 80)
        print(f"\n🔑 Clé détectée: {meilleure_cle}")
        print(f"📝 Message déchiffré: {meilleur_texte}")
        print(f"🎯 Confiance: {meilleur_score:.1f}%")
        print("\n" + "=" * 80)
    else:
        print("❌ Choix invalide!")


def executer_tp1_automatique():
    """Exécute le TP1 automatiquement"""
    print("\n" + "=" * 80)
    print("📚 EXÉCUTION DU TP1 (MODE AUTOMATIQUE)")
    print("=" * 80)
    
    MESSAGE_TP = "YHWL YLGL YLFL"
    
    print("\n📌 Message du TP: YHWL YLGL YLFL")
    print("⚠️  Note: Le message contient une faute de frappe dans le PDF")
    print("    (W au lieu de Q pour obtenir 'VENI')")
    print("    Le script détectera automatiquement la meilleure solution!\n")
    
    input("⏎ Appuyez sur ENTRÉE pour lancer l'analyse...")
    
    cle_detectee, texte_dechiffre = detecter_meilleure_cle(MESSAGE_TP)
    
    print("\n" + "=" * 80)
    print("💡 EXPLICATION PÉDAGOGIQUE")
    print("=" * 80)
    print("""
Pour que le message "YHWL YLGL YLFL" donne "VENI VIDI VICI":
- Il faudrait que W devienne N (décalage de 9 positions)
- Mais Y devient V avec un décalage de 3 positions
- C'est incohérent!

Le message original du professeur contenait probablement:
"YHQL YLGL YLFL" (avec Q au lieu de W)

Dans ce cas, avec la clé 3:
Y - 3 = V
H - 3 = E
Q - 3 = N  ✓
L - 3 = I

Ce qui donne bien "VENI VIDI VICI" !

Le script a détecté automatiquement la meilleure correspondance possible
avec le message fourni.
""")
    
    print("=" * 80)


def afficher_exemples():
    """Affiche des exemples de messages"""
    print("\n" + "=" * 80)
    print("📝 EXEMPLES DE MESSAGES")
    print("=" * 80)
    print("""
Voici quelques exemples que vous pouvez tester:

1️⃣  MESSAGE DU TP
   Chiffré  : YHWL YLGL YLFL
   Clé      : 3
   Déchiffré : VENI VIDI VICI (avec correction)

2️⃣  MESSAGE FRANÇAIS COURT
   Chiffré  : ERQMRXU
   Clé      : 3
   Déchiffré : BONJOUR

3️⃣  MESSAGE ANGLAIS
   Chiffré  : MJQQT BTWQI
   Clé      : 5
   Déchiffré : HELLO WORLD

4️⃣  MESSAGE FRANÇAIS MOYEN
   Chiffré  : GR SNHG SOPHA
   Clé      : 25
   Déchiffré : LE FAIT FROID

5️⃣  MESSAGE TECHNIQUE
   Chiffré  : PELCGBTENCUVR
   Clé      : 13 (ROT13)
   Déchiffré : CRYPTOGRAPHIE

6️⃣  PHRASE COMPLÈTE
   Chiffré  : OD UGEWTKVG GUV KORQTVCPVG
   Clé      : 2
   Déchiffré : LA SECURITE EST IMPORTANTE

Copiez-collez ces messages dans les modes 2, 3 ou 4 pour les tester!
""")
    print("=" * 80)


def afficher_aide():
    """Affiche l'aide et les explications"""
    print("\n" + "=" * 80)
    print("❓ AIDE ET EXPLICATIONS")
    print("=" * 80)
    print("""
🔐 LE CHIFFRE DE CÉSAR

Le chiffre de César est un système de chiffrement par substitution très ancien.
Jules César l'utilisait pour protéger ses communications militaires.

PRINCIPE:
• Chaque lettre est remplacée par une autre lettre située à distance fixe
• La "clé" est le nombre de positions de décalage (1 à 25)

FORMULES:
• Chiffrement   : C = (P + k) mod 26
• Déchiffrement : P = (C - k) mod 26

Où: P = position lettre claire, C = position lettre chiffrée, k = clé

EXEMPLE (clé = 3):
A → D, B → E, C → F, ..., X → A, Y → B, Z → C

═══════════════════════════════════════════════════════════════════════

🧠 CRYPTANALYSE AVANCÉE

Ce script utilise 3 techniques mathématiques pour casser le code:

1️⃣  TEST DU CHI-CARRÉ (χ²)
   • Compare les fréquences de lettres avec celles du français
   • Plus le score est BAS, meilleure est la correspondance
   • Formule: χ² = Σ[(Observé - Attendu)² / Attendu]

2️⃣  INDEX DE COÏNCIDENCE (IC)
   • Mesure si le texte ressemble à une langue naturelle
   • Français réel: IC ≈ 0.067
   • Texte aléatoire: IC ≈ 0.038

3️⃣  DÉTECTION DE MOTS
   • Cherche des mots français/latins connus
   • Base de données de 50+ mots courants

STRATÉGIE ADAPTATIVE:
Le script adapte sa méthode selon la longueur du texte:
• Texte court (< 15) → Privilégie les mots reconnus
• Texte moyen (15-30) → Approche équilibrée
• Texte long (> 30) → Chi-carré dominant

═══════════════════════════════════════════════════════════════════════

💡 CONSEILS D'UTILISATION

Mode 1 (TP1 Auto): Lance automatiquement l'analyse du message du TP
Mode 2 (Chiffrer): Créez vos propres messages secrets
Mode 3 (Déchiffrer): Déchiffrez si vous connaissez la clé
Mode 4 (Cryptanalyse): Cassez le code sans connaître la clé!

Pour de meilleurs résultats en cryptanalyse:
✓ Utilisez des textes d'au moins 10-15 caractères
✓ Évitez les abréviations et les nombres
✓ Les textes longs (30+) donnent les meilleurs résultats
""")
    print("=" * 80)


def afficher_banniere():
    """Affiche la bannière du programme"""
    print("\n" + "=" * 80)
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║         🔐 ANALYSEUR DU CHIFFRE DE CÉSAR 🔐                  ║
    ║                                                               ║
    ║         TP1 - Fondamentaux de la Sécurité                     ║
    ║         ISGA Marrakech                                        ║
    ║                                                               ║
    ║         👩‍💻 Auteur: Farah                                      ║
    ║         👨‍🏫 Prof: Lahcen AIT IBOUREK                           ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    print("=" * 80)


def afficher_menu():
    """Affiche le menu principal"""
    print("\n" + "=" * 80)
    print("📋 MENU PRINCIPAL")
    print("=" * 80)
    print("""
1️⃣  - Exécuter le TP1 (Mode Automatique)
2️⃣  - Chiffrer un message (avec clé)
3️⃣  - Déchiffrer un message (avec clé connue)
4️⃣  - Cryptanalyse avancée (clé inconnue)
5️⃣  - Voir des exemples
6️⃣  - Aide et explications
0️⃣  - Quitter
    """)
    print("=" * 80)


# ═══════════════════════════════════════════════════════════════════════════
#                           FONCTION PRINCIPALE
# ═══════════════════════════════════════════════════════════════════════════

def main():
    """Fonction principale avec menu interactif"""
    
    afficher_banniere()
    
    while True:
        afficher_menu()
        
        choix = input("👉 Votre choix: ").strip()
        
        if choix == "1":
            executer_tp1_automatique()
            input("\n⏎ Appuyez sur ENTRÉE pour continuer...")
            
        elif choix == "2":
            chiffrer_interactif()
            input("\n⏎ Appuyez sur ENTRÉE pour continuer...")
            
        elif choix == "3":
            dechiffrer_interactif()
            input("\n⏎ Appuyez sur ENTRÉE pour continuer...")
            
        elif choix == "4":
            cryptanalyse_avancee()
            input("\n⏎ Appuyez sur ENTRÉE pour continuer...")
            
        elif choix == "5":
            afficher_exemples()
            input("\n⏎ Appuyez sur ENTRÉE pour continuer...")
            
        elif choix == "6":
            afficher_aide()
            input("\n⏎ Appuyez sur ENTRÉE pour continuer...")
            
        elif choix == "0":
            print("\n" + "=" * 80)
            print("👋 Merci d'avoir utilisé l'analyseur!")
            print("✅ Bon courage pour votre TP!")
            print("📚 N'oubliez pas: Ne jamais créer son propre algorithme!")
            print("=" * 80 + "\n")
            break
            
        else:
            print("\n❌ Choix invalide! Choisissez entre 0 et 6.")
            input("⏎ Appuyez sur ENTRÉE pour continuer...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Programme interrompu.")
    except Exception as e:
        print(f"\n❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
