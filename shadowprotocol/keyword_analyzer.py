"""
ShadowProtocol - Analyseur par Mots-Cles

Detection de cibles binaires via dictionnaire de mots-cles.
Analyse approfondie des signatures binaires pour trouver
des points d'injection securises sans patchage aveugle.

Le dictionnaire sert a indiquer l'offset, et le systeme
fait une analyse profonde du binaire pour trouver la bonne
voie. Il ne patch pas aveuglement mais fait un scan et
analyse complete avant de toucher a quoi que ce soit.
"""

import re
from pathlib import Path
from typing import List, Dict, Optional


class KeywordDictionary:
    """Gestion du dictionnaire de mots-cles pour le ciblage binaire.

    Formats acceptes:
    - Fichier .txt avec mots-cles separés par virgule: "mot1", "mot2", "mot3"
    - Fichier .txt avec un mot-cle par ligne
    - Ajout manuel un par un
    """

    def __init__(self, dict_file: Optional[str] = None):
        """Initialiser le dictionnaire de mots-cles.

        Args:
            dict_file: Chemin vers fichier .txt avec mots-cles (separés par virgule)
        """
        self.keywords: List[str] = []
        if dict_file and Path(dict_file).exists():
            self.load_from_file(dict_file)

    def load_from_file(self, path: str) -> bool:
        """Charger les mots-cles depuis un fichier .txt.

        Format:
        - Separes par virgule: "mot1", "mot2", "mot3"
        - Ou un par ligne: mot1\\nmot2\\nmot3

        Args:
            path: Chemin vers le fichier .txt

        Returns:
            True si chargement reussi
        """
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()

            if not content.strip():
                return False

            # Essayer le format separe par virgule d'abord
            if ',' in content:
                raw_keywords = content.split(',')
                self.keywords = []
                for kw in raw_keywords:
                    cleaned = kw.strip().strip('"\'')
                    if cleaned:
                        self.keywords.append(cleaned)
            else:
                self.keywords = [kw.strip() for kw in content.splitlines()
                                 if kw.strip()]

            return len(self.keywords) > 0
        except Exception:
            return False

    def add_keyword(self, keyword: str) -> None:
        """Ajouter un mot-cle manuellement.

        Args:
            keyword: Mot-cle a ajouter
        """
        if keyword and keyword not in self.keywords:
            self.keywords.append(keyword.strip())

    def add_keywords_from_input(self, input_str: str) -> int:
        """Ajouter des mots-cles depuis une chaine saisie par l'utilisateur.

        Accepte les formats: "mot1", "mot2" ou mot1, mot2 ou mot1 mot2

        Args:
            input_str: Chaine avec mots-cles

        Returns:
            Nombre de mots-cles ajoutes
        """
        added = 0
        # Parser les mots-cles separes par virgule ou espace
        if ',' in input_str:
            parts = input_str.split(',')
        else:
            parts = input_str.split()

        for part in parts:
            cleaned = part.strip().strip('"\'')
            if cleaned and cleaned not in self.keywords:
                self.keywords.append(cleaned)
                added += 1

        return added

    def remove_keyword(self, keyword: str) -> None:
        """Retirer un mot-cle."""
        self.keywords = [kw for kw in self.keywords if kw != keyword]

    def save_to_file(self, path: str) -> bool:
        """Sauvegarder les mots-cles dans un fichier .txt."""
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(', '.join(f'"{kw}"' for kw in self.keywords))
            return True
        except Exception:
            return False

    def get_keywords(self) -> List[str]:
        """Retourner une copie de la liste des mots-cles."""
        return self.keywords.copy()

    def is_loaded(self) -> bool:
        """Verifier si des mots-cles sont charges."""
        return len(self.keywords) > 0

    def __len__(self) -> int:
        return len(self.keywords)

    def __repr__(self) -> str:
        return f"KeywordDictionary({self.keywords})"


class BinaryAnalyzer:
    """Analyse binaire approfondie pour le ciblage securise.

    NE PATCH PAS AVEUGLEMENT. Fait un scan complet et une analyse
    profonde du binaire avant de toucher a quoi que ce soit.
    Meme si la cible est trouvee a un offset comme 0x20, le
    systeme verifie le contexte avant de modifier quoi que ce soit
    pour ne pas bousiller inutilement le fichier.
    """

    def __init__(self, binary_path: str):
        """Initialiser l'analyseur pour un binaire.

        Args:
            binary_path: Chemin vers le fichier binaire
        """
        self.binary_path = Path(binary_path)
        self.binary_data: Optional[bytes] = None
        self._load_binary()

    def _load_binary(self) -> bool:
        """Charger le fichier binaire en memoire.

        Returns:
            True si chargement reussi
        """
        try:
            with open(self.binary_path, 'rb') as f:
                self.binary_data = f.read()
            return len(self.binary_data) > 0
        except Exception:
            return False

    def is_loaded(self) -> bool:
        """Verifier si le binaire est charge."""
        return self.binary_data is not None and len(self.binary_data) > 0

    def find_keyword_offsets(self, keyword: str) -> List[int]:
        """Trouver toutes les occurrences d'un mot-cle dans le binaire.

        Le mot-cle peut etre:
        - Une chaine UTF-8 (recherche textuelle)
        - Un pattern hex (format: 0xHH ou HH ou \\xHH\\xHH)

        Args:
            keyword: Mot-cle a chercher

        Returns:
            Liste des offsets ou le mot-cle est trouve
        """
        if not self.binary_data:
            return []

        offsets = []

        # Determiner le type de recherche
        search_bytes = self._parse_keyword(keyword)
        if not search_bytes:
            return []

        # Trouver toutes les occurrences
        start = 0
        while True:
            pos = self.binary_data.find(search_bytes, start)
            if pos == -1:
                break
            offsets.append(pos)
            start = pos + 1

        return offsets

    def _parse_keyword(self, keyword: str) -> Optional[bytes]:
        """Parser un mot-cle en bytes pour la recherche.

        Supporte:
        - Chaines UTF-8 simples
        - Patterns hex: "0x30" -> un byte, "\\x30\\x20" -> deux bytes
        - Format direct hex: "30 20" ou "3020"
        """
        if not keyword:
            return None

        # Essayer le format hex multiple: \xHH\xHH (literal backslash x)
        if '\\x' in keyword or keyword.startswith('x'):
            try:
                # Supporte: \x30\x20 ou x30x20
                hex_str = keyword.replace('\\x', '').replace('x', '')
                if hex_str and all(c in '0123456789abcdefABCDEF' for c in hex_str):
                    # Grouper par paires de caractères
                    pairs = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
                    return bytes(int(pair, 16) for pair in pairs)
            except (ValueError, TypeError, AttributeError):
                pass

        # Essayer le format 0xHH ou 0xHHHH
        if keyword.startswith('0x'):
            try:
                # Peut être un ou plusieurs bytes
                hex_part = keyword[2:]
                if len(hex_part) <= 8 and all(c in '0123456789abcdefABCDEF' for c in hex_part):
                    byte_val = int(hex_part, 16)
                    # Encoder en bytes (little-endian ou big-endian?)
                    if byte_val <= 0xFF:
                        return bytes([byte_val])
                    elif byte_val <= 0xFFFF:
                        return byte_val.to_bytes(2, 'big')
                    elif byte_val <= 0xFFFFFFFF:
                        return byte_val.to_bytes(4, 'big')
            except (ValueError, TypeError):
                pass

        # Par defaut: recherche textuelle UTF-8
        try:
            return keyword.encode('utf-8', errors='ignore')
        except Exception:
            return None

    def analyze_context(self, offset: int, context_size: int = 64) -> Dict:
        """Analyser le contexte binaire autour d'un offset.

        Args:
            offset: Offset a analyser
            context_size: Octets a lire avant/apres

        Returns:
            Dictionnaire avec l'analyse du contexte
        """
        if not self.binary_data or offset < 0:
            return {}

        start = max(0, offset - context_size)
        end = min(len(self.binary_data), offset + context_size)

        context = self.binary_data[start:end]
        before = self.binary_data[max(0, offset - 16):offset]
        after = self.binary_data[offset:min(len(self.binary_data), offset + 16)]

        return {
            'offset': offset,
            'offset_hex': hex(offset),
            'context': context.hex(),
            'before': before.hex(),
            'after': after.hex(),
            'size': len(context),
            'is_safe': self._validate_offset_safety(offset)
        }

    def _validate_offset_safety(self, offset: int) -> bool:
        """Valider si un offset est sur pour le patchage.

        Verifications:
        - Pas dans les regions d'en-tete ELF (< 64 octets)
        - Pas sur les bytes magiques ELF
        - Contexte suffisant autour de l'offset
        - L'offset est dans les limites du fichier

        Args:
            offset: Offset a valider

        Returns:
            True si l'offset semble sur
        """
        if not self.binary_data:
            return False

        # Verifier les limites
        if offset < 64 or offset >= len(self.binary_data) - 8:
            return False

        # Verifier le contexte minimal
        return offset + 8 <= len(self.binary_data)

    def scan_for_safe_patches(self, keyword: str,
                              min_context: int = 8) -> List[Dict]:
        """Scanner le binaire pour des points de patchage sur autour d'un mot-cle.

        NE PATCH PAS - analyse uniquement et rapporte les resultats.

        Args:
            keyword: Mot-cle a chercher
            min_context: Minimum d'octets necessaires autour de l'offset

        Returns:
            Liste de candidats de patchage sur avec metadonnees
        """
        offsets = self.find_keyword_offsets(keyword)
        safe_patches = []

        for offset in offsets:
            analysis = self.analyze_context(offset)
            if analysis.get('is_safe'):
                safe_patches.append({
                    'keyword': keyword,
                    'offset': offset,
                    'offset_hex': hex(offset),
                    'analysis': analysis,
                    'status': 'SAFE'
                })
            else:
                safe_patches.append({
                    'keyword': keyword,
                    'offset': offset,
                    'offset_hex': hex(offset),
                    'analysis': analysis,
                    'status': 'UNSAFE'
                })

        return safe_patches

    def deep_scan(self, keywords: List[str]) -> Dict[str, List[Dict]]:
        """Effectuer un scan approfondi du binaire avec plusieurs mots-cles.

        NE PATCH PAS - analyse uniquement et rapporte les resultats.
        Chaque mot-cle est recherche, et chaque occurrence est
        analysee pour determiner si elle est sur pour le patchage.

        Args:
            keywords: Liste de mots-cles a chercher

        Returns:
            Dictionnaire mappant chaque mot-cle a ses points de patchage
        """
        results = {}
        for keyword in keywords:
            results[keyword] = self.scan_for_safe_patches(keyword)
        return results

    def deep_scan_with_pattern(self, pattern: str) -> List[Dict]:
        """Scan approfondi avec un pattern regex dans le binaire desassemblable.

        Args:
            pattern: Pattern regex a chercher

        Returns:
            Liste de resultats avec offset et contexte
        """
        if not self.binary_data:
            return []

        results = []
        try:
            # Recherche du pattern comme chaine UTF-8 dans le binaire
            regex = re.compile(pattern, re.IGNORECASE)
            text_data = self.binary_data.decode('utf-8', errors='ignore')

            for match in regex.finditer(text_data):
                # Calculer l'offset reel dans le binaire
                # Attention: l'offset dans le texte decode peut differer
                # a cause des caracteres multi-octets
                char_offset = match.start()
                # Estimer l'offset binaire (approximatif)
                byte_offset = len(text_data[:char_offset].encode('utf-8'))

                analysis = self.analyze_context(byte_offset)
                results.append({
                    'keyword': pattern,
                    'offset': byte_offset,
                    'offset_hex': hex(byte_offset),
                    'match': match.group()[:100],
                    'analysis': analysis,
                    'status': 'SAFE' if analysis.get('is_safe') else 'UNSAFE'
                })
        except Exception:
            pass

        return results

    def verify_patch_safety(self, offset: int, patch_size: int) -> bool:
        """Verifier si un patch a un offset est sur.

        Args:
            offset: Offset du patch
            patch_size: Taille du patch

        Returns:
            True si sur de patcher
        """
        if not self.binary_data:
            return False

        # Verifier les limites
        if offset < 0 or offset + patch_size > len(self.binary_data):
            return False

        # Verifier que ce n'est pas dans une region critique
        if offset < 64 and self.binary_data[:4] == b'\x7fELF':
            return False

        return self._validate_offset_safety(offset)

    def get_binary_info(self) -> Dict:
        """Obtenir les informations du fichier binaire.

        Returns:
            Dictionnaire avec les metadonnees du fichier
        """
        if not self.binary_data:
            return {}

        is_elf = self.binary_data[:4] == b'\x7fELF'
        is_zip = self.binary_data[:2] == b'PK'

        return {
            'path': str(self.binary_path),
            'size': len(self.binary_data),
            'is_elf': is_elf,
            'is_apk': is_zip,
            'header': self.binary_data[:16].hex()
        }
