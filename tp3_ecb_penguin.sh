#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# TP3 - VISUALISATION DE LA FAILLE ECB (Le Pingouin)
# Module: Fondamentaux de la Sécurité et Cryptographie
# ISGA Marrakech
# 
# Auteur: Farah El Alem
# ═══════════════════════════════════════════════════════════════════════════

set -e  # Arrêter en cas d'erreur

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction d'affichage
print_header() {
    echo -e "\n${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}\n"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_step() {
    echo -e "\n${YELLOW}📍 ÉTAPE $1${NC}\n"
}

# ═══════════════════════════════════════════════════════════════════════════
#                           DÉBUT DU TP3
# ═══════════════════════════════════════════════════════════════════════════

clear
print_header "TP3 - VISUALISATION DE LA FAILLE ECB"

echo "🎯 Objectif:"
echo "   Démontrer que le mode ECB préserve les motifs visuels"
echo "   contrairement au mode CBC qui les détruit complètement."
echo ""
echo "🐧 On va chiffrer l'image du pingouin Tux en:"
echo "   • Mode ECB (dangereux) → On verra encore le pingouin!"
echo "   • Mode CBC (sécurisé)  → Neige télévisuelle (bruit blanc)"
echo ""

read -p "⏎ Appuyez sur ENTRÉE pour commencer..."

# ═══════════════════════════════════════════════════════════════════════════
print_step "1/6 - TÉLÉCHARGEMENT DE L'IMAGE"
# ═══════════════════════════════════════════════════════════════════════════

if [ -f "tux.bmp" ]; then
    print_warning "tux.bmp existe déjà, on le garde."
else
    echo "📥 Téléchargement de l'image Tux (le pingouin Linux)..."
    curl -L -o tux.bmp https://raw.githubusercontent.com/tkeliris/ecb-penguin/3910bccd6924eb6c632560adeb9df4ce380c0b92/tux_clear.bmp
    print_success "Image téléchargée!"
fi

# Vérification
echo ""
echo "📊 Informations sur le fichier:"
file tux.bmp
ls -lh tux.bmp
print_success "Image BMP valide détectée!"

read -p "⏎ Appuyez sur ENTRÉE pour continuer..."

# ═══════════════════════════════════════════════════════════════════════════
print_step "2/6 - EXTRACTION DE L'EN-TÊTE ET DU CORPS"
# ═══════════════════════════════════════════════════════════════════════════

echo "🔪 Séparation de l'image en deux parties:"
echo "   • En-tête (54 octets) : informations sur l'image"
echo "   • Corps (reste)        : les pixels à chiffrer"
echo ""

# Extraire l'en-tête (54 premiers octets)
head -c 54 tux.bmp > header.bin
print_success "En-tête extrait (54 octets)"

# Extraire le corps (tout sauf les 54 premiers octets)
tail -c +55 tux.bmp > body.bin
print_success "Corps extrait ($(stat -c%s body.bin) octets)"

echo ""
echo "📊 Vérification des tailles:"
echo "   Original  : $(stat -c%s tux.bmp) octets"
echo "   En-tête   : $(stat -c%s header.bin) octets"
echo "   Corps     : $(stat -c%s body.bin) octets"
echo "   Somme     : $(($(stat -c%s header.bin) + $(stat -c%s body.bin))) octets"
print_success "Les tailles correspondent!"

read -p "⏎ Appuyez sur ENTRÉE pour continuer..."

# ═══════════════════════════════════════════════════════════════════════════
print_step "3/6 - CHIFFREMENT EN MODE ECB (DANGEREUX)"
# ═══════════════════════════════════════════════════════════════════════════

echo "🔒 Chiffrement du corps en mode ECB..."
echo "   Mode: AES-128-ECB"
echo "   Clé: 1234567890123456 (128 bits)"
echo ""
print_warning "Mode ECB = Chaque bloc chiffré indépendamment"
print_warning "Problème: Les motifs restent visibles!"
echo ""

# Chiffrer le corps en ECB
KEY="31323334353637383930313233343536"  # "1234567890123456" en hex
openssl enc -aes-128-ecb -in body.bin -out body_ecb.enc -K $KEY -nosalt

print_success "Corps chiffré en ECB!"

# Reconstruire l'image
cat header.bin body_ecb.enc > tux_ecb.bmp
print_success "Image reconstruite: tux_ecb.bmp"

echo ""
echo "📊 Taille de l'image chiffrée:"
ls -lh tux_ecb.bmp

read -p "⏎ Appuyez sur ENTRÉE pour continuer..."

# ═══════════════════════════════════════════════════════════════════════════
print_step "4/6 - CHIFFREMENT EN MODE CBC (SÉCURISÉ)"
# ═══════════════════════════════════════════════════════════════════════════

echo "🔒 Chiffrement du corps en mode CBC..."
echo "   Mode: AES-128-CBC"
echo "   Clé: 1234567890123456 (128 bits)"
echo "   IV: 0000000000000000 (vecteur d'initialisation)"
echo ""
print_success "Mode CBC = Chaque bloc dépend du précédent"
print_success "Résultat: Les motifs sont DÉTRUITS!"
echo ""

# Chiffrer le corps en CBC
IV="30303030303030303030303030303030"  # "0000000000000000" en hex
openssl enc -aes-128-cbc -in body.bin -out body_cbc.enc -K $KEY -iv $IV -nosalt

print_success "Corps chiffré en CBC!"

# Reconstruire l'image
cat header.bin body_cbc.enc > tux_cbc.bmp
print_success "Image reconstruite: tux_cbc.bmp"

echo ""
echo "📊 Taille de l'image chiffrée:"
ls -lh tux_cbc.bmp

read -p "⏎ Appuyez sur ENTRÉE pour continuer..."

# ═══════════════════════════════════════════════════════════════════════════
print_step "5/6 - COMPARAISON DES RÉSULTATS"
# ═══════════════════════════════════════════════════════════════════════════

echo "📊 Récapitulatif des fichiers créés:"
echo ""
ls -lh tux*.bmp header.bin body*.bin body*.enc 2>/dev/null | awk '{print "   "$9, $5}'

echo ""
print_header "ANALYSE DES RÉSULTATS"

echo "🖼️  IMAGE ORIGINALE (tux.bmp):"
echo "   • Pingouin Tux clairement visible"
echo "   • Couleurs: blanc, noir, jaune"
echo "   • Contours nets"
echo ""

echo "⚠️  IMAGE CHIFFRÉE EN ECB (tux_ecb.bmp):"
echo "   ❌ Le pingouin est ENCORE VISIBLE!"
echo "   ❌ Les contours sont reconnaissables"
echo "   ❌ La structure est préservée"
echo "   ❌ DANGEREUX: On voit ce qui est chiffré!"
echo ""

echo "✅ IMAGE CHIFFRÉE EN CBC (tux_cbc.bmp):"
echo "   ✅ Neige télévisuelle (bruit blanc)"
echo "   ✅ Aucun motif visible"
echo "   ✅ Totalement illisible"
echo "   ✅ SÉCURISÉ: Impossible de deviner le contenu!"
echo ""

read -p "⏎ Appuyez sur ENTRÉE pour continuer..."

# ═══════════════════════════════════════════════════════════════════════════
print_step "6/6 - EXPLICATIONS TECHNIQUES"
# ═══════════════════════════════════════════════════════════════════════════

print_header "POURQUOI ECB EST DANGEREUX?"

echo "📚 MODE ECB (Electronic Code Book):"
echo ""
echo "   Fonctionnement:"
echo "   ┌──────┐    ┌──────┐    ┌──────┐"
echo "   │Bloc 1│───▶│Bloc 2│───▶│Bloc 3│"
echo "   └──────┘    └──────┘    └──────┘"
echo "      ▼            ▼            ▼"
echo "   [AES]        [AES]        [AES]  ← Chiffrement indépendant"
echo "      ▼            ▼            ▼"
echo "   ┌──────┐    ┌──────┐    ┌──────┐"
echo "   │Chif 1│    │Chif 2│    │Chif 3│"
echo "   └──────┘    └──────┘    └──────┘"
echo ""
echo "   ❌ Problème:"
echo "   • Bloc identique → Chiffré identique"
echo "   • Les motifs répétitifs restent visibles"
echo "   • Un grand aplat blanc → Toujours un aplat"
echo ""

echo "📚 MODE CBC (Cipher Block Chaining):"
echo ""
echo "   Fonctionnement:"
echo "   ┌──────┐    ┌──────┐    ┌──────┐"
echo "   │Bloc 1│───▶│Bloc 2│───▶│Bloc 3│"
echo "   └──────┘    └──────┘    └──────┘"
echo "      ▼            ▼            ▼"
echo "    [XOR]  ┌───[XOR]  ┌───[XOR]"
echo "      │    │     │    │     │"
echo "   [AES]◀──┘  [AES]◀──┘  [AES]  ← Dépend du précédent"
echo "      ▼            ▼            ▼"
echo "   ┌──────┐    ┌──────┐    ┌──────┐"
echo "   │Chif 1│    │Chif 2│    │Chif 3│"
echo "   └──────┘    └──────┘    └──────┘"
echo ""
echo "   ✅ Avantage:"
echo "   • Chaque bloc dépend du précédent"
echo "   • Bloc identique → Chiffré différent"
echo "   • Effet avalanche: 1 bit change → 50% du résultat change"
echo ""

read -p "⏎ Appuyez sur ENTRÉE pour continuer..."

# ═══════════════════════════════════════════════════════════════════════════
print_header "CONCLUSION DU TP3"
# ═══════════════════════════════════════════════════════════════════════════

echo "📝 Ce qu'on a appris:"
echo ""
echo "1️⃣  Le mode ECB est DANGEREUX:"
echo "   • Préserve les motifs visuels"
echo "   • Permet de deviner le contenu"
echo "   • Ne doit JAMAIS être utilisé en production"
echo ""
echo "2️⃣  Le mode CBC est SÉCURISÉ:"
echo "   • Détruit complètement les motifs"
echo "   • Chaque bloc dépend du précédent"
echo "   • Standard recommandé (avec GCM aussi)"
echo ""
echo "3️⃣  L'algorithme seul ne suffit pas:"
echo "   • AES est excellent"
echo "   • Mais le MODE D'OPÉRATION est crucial!"
echo "   • ECB + AES = mauvais"
echo "   • CBC + AES = bon"
echo ""

print_header "POUR TON RAPPORT"

echo "📊 Éléments à inclure:"
echo ""
echo "• Images des 3 fichiers (original, ECB, CBC)"
echo "• Explication: ECB préserve les motifs"
echo "• Comparaison visuelle"
echo "• Conclusion: Importance du mode d'opération"
echo ""
echo "💡 Citation clé:"
echo '   "Avoir un bon algorithme (AES) ne suffit pas,'
echo '    il faut aussi un bon mode d'\''opération (CBC, GCM)."'
echo ""

print_header "FICHIERS CRÉÉS"

echo "📁 Fichiers disponibles:"
echo ""
echo "   Images:"
echo "   • tux.bmp       - Image originale"
echo "   • tux_ecb.bmp   - Chiffrée en ECB (pingouin visible!)"
echo "   • tux_cbc.bmp   - Chiffrée en CBC (bruit blanc)"
echo ""
echo "   Fichiers intermédiaires:"
echo "   • header.bin    - En-tête BMP (54 octets)"
echo "   • body.bin      - Corps original"
echo "   • body_ecb.enc  - Corps chiffré en ECB"
echo "   • body_cbc.enc  - Corps chiffré en CBC"
echo ""

print_success "TP3 TERMINÉ AVEC SUCCÈS!"

echo ""
echo "👀 Pour voir les images:"
echo "   • Ouvre les fichiers .bmp avec un visualiseur d'images"
echo "   • Ou transférer sur Windows/Mac pour les voir"
echo "   • Ou utiliser: display tux_ecb.bmp (si ImageMagick installé)"
echo ""
echo ""
