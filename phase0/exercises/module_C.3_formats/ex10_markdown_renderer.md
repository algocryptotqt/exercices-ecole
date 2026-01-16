# Exercice C.3.0-c : markdown_renderer

**Module :**
C.3.0 — Data Formats: Markdown Processing

**Concept :**
c — Headers, bold, italic, lists, links, images, code blocks, tables

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Python 3.14

**Prerequis :**
- Expressions regulieres basiques
- Manipulation de strings
- Structures de donnees (listes)

**Domaines :**
Encodage, Struct, FS

**Duree estimee :**
40 min

**XP Base :**
60

**Complexite :**
T2 O(n) x S2 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
`markdown_renderer.py`

**Fonctions autorisees :**
- Module `re` (expressions regulieres)
- Toutes les fonctions Python natives
- Methodes de string

**Fonctions interdites :**
- Bibliotheques Markdown externes (markdown, mistune, etc.)
- `eval`, `exec`

---

### 1.2 Consigne

#### Section Culture : "README or Die"

**"A well-documented repo is a happy repo" — Linus Torvalds (probablement)**

Tu ouvres un projet GitHub. Pas de README. Pas de documentation. Juste du code obscur. C'est le cauchemar de tout developpeur. Markdown est le superheros silencieux qui transforme du texte brut en documentation lisible.

Invente par John Gruber en 2004, Markdown est devenu LE standard de facto pour la documentation technique. GitHub, Stack Overflow, Reddit, Discord... tout utilise une variante de Markdown.

*"Talk is cheap. Show me the README.md"*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un convertisseur Markdown vers HTML basique :

1. **`md_to_html(content: str) -> str`** : Conversion complete Markdown vers HTML
2. **`parse_headers(line: str) -> str`** : Convertit les headers (`#` a `######`)
3. **`parse_inline(text: str) -> str`** : Convertit bold, italic, code inline, liens, images
4. **`parse_lists(lines: list[str]) -> str`** : Convertit les listes ordonnees et non-ordonnees
5. **`parse_code_blocks(content: str) -> str`** : Convertit les blocs de code
6. **`parse_tables(lines: list[str]) -> str`** : Convertit les tableaux

**Entree :**
```python
def md_to_html(content: str) -> str:
    """
    Convert Markdown to HTML.

    Supports:
    - Headers: # to ######
    - Bold: **text** or __text__
    - Italic: *text* or _text_
    - Code inline: `code`
    - Links: [text](url)
    - Images: ![alt](url)
    - Unordered lists: - item or * item
    - Ordered lists: 1. item
    - Code blocks: ```language\ncode\n```
    - Tables: | col1 | col2 |
    - Horizontal rules: --- or ***
    - Blockquotes: > text
    """
    pass
```

**Sortie :**
- HTML valide sans doctype (juste le contenu)
- Chaque element Markdown converti en son equivalent HTML

**Contraintes :**
- Les elements inline peuvent etre imbriques : `**bold and *italic***`
- Les blocs de code preservent le contenu tel quel (pas de parsing inline)
- Les tableaux ont un header et un body
- Gerer les paragraphes (texte separe par lignes vides)

**Exemples :**

| Markdown | HTML |
|----------|------|
| `# Title` | `<h1>Title</h1>` |
| `**bold**` | `<strong>bold</strong>` |
| `*italic*` | `<em>italic</em>` |
| `` `code` `` | `<code>code</code>` |
| `[link](url)` | `<a href="url">link</a>` |
| `![alt](img)` | `<img src="img" alt="alt">` |
| `- item` | `<ul><li>item</li></ul>` |
| `1. item` | `<ol><li>item</li></ol>` |

---

### 1.3 Prototype

```python
def md_to_html(content: str) -> str:
    pass

def parse_headers(line: str) -> str:
    pass

def parse_inline(text: str) -> str:
    pass

def parse_lists(lines: list[str]) -> str:
    pass

def parse_code_blocks(content: str) -> str:
    pass

def parse_tables(lines: list[str]) -> str:
    pass
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Markdown a ete cree pour les emails !**

John Gruber voulait un format qui soit lisible meme sans rendu. Les asterisques pour le gras mimaient deja ce qu'on faisait dans les emails : *emphasis* et **strong emphasis**.

**GitHub Flavored Markdown (GFM) est devenu le standard de facto**

La specification originale de Gruber etait vague. GitHub a ajoute les tables, les code blocks avec syntaxe, les task lists... et tout le monde a suivi.

**CommonMark essaie de standardiser Markdown**

Apres des annees de chaos ou chaque implementation faisait differemment, CommonMark tente de creer une spec rigoureuse. Spoiler : c'est complique.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Developer** | README, documentation technique, issues GitHub |
| **Technical Writer** | Documentation produit, wikis |
| **Content Creator** | Blogs (Jekyll, Hugo), newsletters |
| **Data Scientist** | Jupyter notebooks, rapports |
| **DevRel** | Tutorials, guides, articles techniques |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ ls
markdown_renderer.py  test_markdown.py

$ python test_markdown.py
Test headers: OK
Test bold and italic: OK
Test links and images: OK
Test lists: OK
Test code blocks: OK
Test tables: OK
Test full document: OK
All tests passed!
```

---

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★★☆☆☆☆☆ (5/10)

**Recompense :**
XP x2

**Domaines Bonus :**
`Struct`, `Algo`

#### 3.1.1 Consigne Bonus

**"Full Featured Markdown Engine"**

**Ta mission bonus :**

1. **`md_to_ast(content: str) -> dict`** : Parse Markdown en AST (Abstract Syntax Tree)
2. **`ast_to_html(ast: dict) -> str`** : Render AST vers HTML
3. **`extract_toc(content: str) -> list`** : Extraire table of contents des headers
4. **`syntax_highlight(code: str, lang: str) -> str`** : Coloration syntaxique basique

**Exemples :**

| Input | Fonction | Output |
|-------|----------|--------|
| `"# A\n## B"` | `extract_toc` | `[{"level":1,"text":"A"},{"level":2,"text":"B"}]` |

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | header_h1 | `# Title` | `<h1>Title</h1>` | 5 | Headers |
| 2 | header_h6 | `###### Small` | `<h6>Small</h6>` | 5 | Headers |
| 3 | bold_asterisk | `**bold**` | `<strong>bold</strong>` | 5 | Inline |
| 4 | bold_underscore | `__bold__` | `<strong>bold</strong>` | 5 | Inline |
| 5 | italic_asterisk | `*italic*` | `<em>italic</em>` | 5 | Inline |
| 6 | italic_underscore | `_italic_` | `<em>italic</em>` | 5 | Inline |
| 7 | code_inline | `` `code` `` | `<code>code</code>` | 5 | Inline |
| 8 | link | `[text](url)` | `<a href="url">text</a>` | 8 | Links |
| 9 | image | `![alt](src)` | `<img src="src" alt="alt">` | 8 | Images |
| 10 | ul_basic | `- item` | `<ul><li>item</li></ul>` | 8 | Lists |
| 11 | ol_basic | `1. item` | `<ol><li>item</li></ol>` | 8 | Lists |
| 12 | code_block | ` ```py\ncode\n``` ` | `<pre><code>...</code></pre>` | 10 | Blocks |
| 13 | table | `\| a \| b \|` | `<table>...</table>` | 10 | Tables |
| 14 | blockquote | `> quote` | `<blockquote>quote</blockquote>` | 5 | Blocks |
| 15 | hr | `---` | `<hr>` | 3 | Misc |
| 16 | nested | `**_both_**` | `<strong><em>both</em></strong>` | 5 | Complex |

**Total : 100 points**

---

### 4.2 test_markdown.py

```python
import sys
sys.path.insert(0, '.')
from markdown_renderer import (
    md_to_html, parse_headers, parse_inline,
    parse_lists, parse_code_blocks, parse_tables
)

def test_headers():
    assert '<h1>Title</h1>' in md_to_html('# Title')
    assert '<h2>Sub</h2>' in md_to_html('## Sub')
    assert '<h6>Tiny</h6>' in md_to_html('###### Tiny')
    print("Test headers: OK")

def test_bold_and_italic():
    assert '<strong>bold</strong>' in md_to_html('**bold**')
    assert '<strong>bold</strong>' in md_to_html('__bold__')
    assert '<em>italic</em>' in md_to_html('*italic*')
    assert '<em>italic</em>' in md_to_html('_italic_')
    print("Test bold and italic: OK")

def test_links_and_images():
    result = md_to_html('[link](http://example.com)')
    assert '<a href="http://example.com">link</a>' in result

    result = md_to_html('![alt text](image.png)')
    assert '<img' in result and 'src="image.png"' in result
    print("Test links and images: OK")

def test_lists():
    ul = md_to_html('- item1\n- item2')
    assert '<ul>' in ul and '<li>item1</li>' in ul

    ol = md_to_html('1. first\n2. second')
    assert '<ol>' in ol and '<li>first</li>' in ol
    print("Test lists: OK")

def test_code_blocks():
    code = md_to_html('```python\nprint("hello")\n```')
    assert '<pre>' in code and '<code>' in code
    assert 'print("hello")' in code
    print("Test code blocks: OK")

def test_tables():
    md = """| Name | Age |
| --- | --- |
| Alice | 30 |
| Bob | 25 |"""
    result = md_to_html(md)
    assert '<table>' in result
    assert '<th>' in result or '<td>' in result
    print("Test tables: OK")

def test_full_document():
    md = """# Welcome

This is **bold** and *italic*.

## Features

- Feature 1
- Feature 2

[Link](http://example.com)
"""
    result = md_to_html(md)
    assert '<h1>Welcome</h1>' in result
    assert '<strong>bold</strong>' in result
    assert '<h2>Features</h2>' in result
    assert '<ul>' in result
    print("Test full document: OK")

if __name__ == "__main__":
    test_headers()
    test_bold_and_italic()
    test_links_and_images()
    test_lists()
    test_code_blocks()
    test_tables()
    test_full_document()
    print("\nAll tests passed!")
```

---

### 4.3 Solution de reference

```python
import re

def parse_headers(line: str) -> str:
    """Convert header lines."""
    match = re.match(r'^(#{1,6})\s+(.+)$', line)
    if match:
        level = len(match.group(1))
        text = match.group(2)
        return f'<h{level}>{parse_inline(text)}</h{level}>'
    return None

def parse_inline(text: str) -> str:
    """Convert inline elements: bold, italic, code, links, images."""
    # Images first (before links, as they start with !)
    text = re.sub(r'!\[([^\]]*)\]\(([^)]+)\)', r'<img src="\2" alt="\1">', text)

    # Links
    text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', text)

    # Code inline (before bold/italic to avoid conflicts)
    text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)

    # Bold (** or __)
    text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'__([^_]+)__', r'<strong>\1</strong>', text)

    # Italic (* or _)
    text = re.sub(r'\*([^*]+)\*', r'<em>\1</em>', text)
    text = re.sub(r'_([^_]+)_', r'<em>\1</em>', text)

    return text

def parse_code_blocks(content: str) -> str:
    """Convert fenced code blocks."""
    def replace_code_block(match):
        lang = match.group(1) or ''
        code = match.group(2)
        # Escape HTML in code
        code = code.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        if lang:
            return f'<pre><code class="language-{lang}">{code}</code></pre>'
        return f'<pre><code>{code}</code></pre>'

    pattern = r'```(\w*)\n(.*?)\n```'
    return re.sub(pattern, replace_code_block, content, flags=re.DOTALL)

def parse_lists(lines: list[str]) -> tuple[str, int]:
    """Parse list starting at current position. Returns (html, lines_consumed)."""
    result = []
    i = 0
    list_type = None

    while i < len(lines):
        line = lines[i]

        # Unordered list item
        ul_match = re.match(r'^[\-\*]\s+(.+)$', line)
        if ul_match:
            if list_type is None:
                list_type = 'ul'
                result.append('<ul>')
            elif list_type != 'ul':
                break
            result.append(f'<li>{parse_inline(ul_match.group(1))}</li>')
            i += 1
            continue

        # Ordered list item
        ol_match = re.match(r'^\d+\.\s+(.+)$', line)
        if ol_match:
            if list_type is None:
                list_type = 'ol'
                result.append('<ol>')
            elif list_type != 'ol':
                break
            result.append(f'<li>{parse_inline(ol_match.group(1))}</li>')
            i += 1
            continue

        # Non-list line
        break

    if list_type:
        result.append(f'</{list_type}>')

    return '\n'.join(result), i

def parse_tables(lines: list[str]) -> tuple[str, int]:
    """Parse table. Returns (html, lines_consumed)."""
    if not lines or '|' not in lines[0]:
        return '', 0

    result = ['<table>']
    i = 0

    # Header row
    if i < len(lines) and '|' in lines[i]:
        cells = [c.strip() for c in lines[i].split('|')[1:-1]]
        result.append('<thead><tr>')
        for cell in cells:
            result.append(f'<th>{parse_inline(cell)}</th>')
        result.append('</tr></thead>')
        i += 1

    # Separator row (skip)
    if i < len(lines) and re.match(r'^[\|\s\-:]+$', lines[i]):
        i += 1

    # Body rows
    result.append('<tbody>')
    while i < len(lines) and '|' in lines[i]:
        cells = [c.strip() for c in lines[i].split('|')[1:-1]]
        result.append('<tr>')
        for cell in cells:
            result.append(f'<td>{parse_inline(cell)}</td>')
        result.append('</tr>')
        i += 1
    result.append('</tbody>')

    result.append('</table>')
    return '\n'.join(result), i

def md_to_html(content: str) -> str:
    """Convert Markdown to HTML."""
    # First, handle code blocks (preserve content)
    content = parse_code_blocks(content)

    lines = content.split('\n')
    result = []
    i = 0
    in_paragraph = False
    paragraph_lines = []

    def flush_paragraph():
        nonlocal paragraph_lines, in_paragraph
        if paragraph_lines:
            text = ' '.join(paragraph_lines)
            result.append(f'<p>{parse_inline(text)}</p>')
            paragraph_lines = []
            in_paragraph = False

    while i < len(lines):
        line = lines[i]

        # Empty line - flush paragraph
        if not line.strip():
            flush_paragraph()
            i += 1
            continue

        # Already processed code block
        if '<pre><code' in line:
            flush_paragraph()
            result.append(line)
            i += 1
            continue

        # Header
        header = parse_headers(line)
        if header:
            flush_paragraph()
            result.append(header)
            i += 1
            continue

        # Horizontal rule
        if re.match(r'^(\-{3,}|\*{3,}|_{3,})$', line.strip()):
            flush_paragraph()
            result.append('<hr>')
            i += 1
            continue

        # Blockquote
        bq_match = re.match(r'^>\s*(.*)$', line)
        if bq_match:
            flush_paragraph()
            result.append(f'<blockquote>{parse_inline(bq_match.group(1))}</blockquote>')
            i += 1
            continue

        # List
        if re.match(r'^[\-\*]\s+', line) or re.match(r'^\d+\.\s+', line):
            flush_paragraph()
            list_html, consumed = parse_lists(lines[i:])
            result.append(list_html)
            i += consumed
            continue

        # Table
        if '|' in line and i + 1 < len(lines) and re.match(r'^[\|\s\-:]+$', lines[i + 1]):
            flush_paragraph()
            table_html, consumed = parse_tables(lines[i:])
            result.append(table_html)
            i += consumed
            continue

        # Regular text - add to paragraph
        paragraph_lines.append(line)
        in_paragraph = True
        i += 1

    flush_paragraph()
    return '\n'.join(result)
```

---

### 4.5 Solutions refusees (avec explications)

**Refus 1 : Utilisation d'une bibliotheque Markdown**

```python
# REFUSE : Bibliotheque externe interdite !
import markdown

def md_to_html(content: str) -> str:
    return markdown.markdown(content)
```
**Pourquoi refuse :** L'exercice demande d'implementer le parsing manuellement.

**Refus 2 : Regex sans gestion des cas imbriques**

```python
# REFUSE : Ne gere pas l'ordre des operations !
def parse_inline(text: str) -> str:
    text = re.sub(r'\*([^*]+)\*', r'<em>\1</em>', text)
    text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', text)
    # Probleme: **bold** devient <em><em>bold</em></em>
```
**Pourquoi refuse :** L'ordre des regles est important pour eviter les conflits.

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Headers sans espace**

```python
# Mutant A : N'exige pas d'espace apres #
def parse_headers(line: str) -> str:
    match = re.match(r'^(#{1,6})(.+)$', line)  # Pas de \s+ !
    # "#Title" match alors que ca ne devrait pas
```

**Mutant B (Safety) : Code blocks pas echappes**

```python
# Mutant B : HTML dans le code non echappe
def parse_code_blocks(content: str) -> str:
    # Ne fait pas: code.replace('<', '&lt;')
    return f'<pre><code>{code}</code></pre>'  # XSS possible !
```

**Mutant C (Logic) : Ordre inline incorrect**

```python
# Mutant C : Italic avant bold
def parse_inline(text: str) -> str:
    text = re.sub(r'\*([^*]+)\*', r'<em>\1</em>', text)  # D'abord
    text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', text)  # Ensuite
    # **bold** devient <em><em>bold</em></em>
```

**Mutant D (Resource) : Regex catastrophique**

```python
# Mutant D : Backtracking exponentiel
def parse_inline(text: str) -> str:
    text = re.sub(r'\*+([^*]*)\*+', r'<em>\1</em>', text)  # ReDoS !
```

**Mutant E (Return) : Images comme liens**

```python
# Mutant E : Confond images et liens
def parse_inline(text: str) -> str:
    # Ne distingue pas ![alt](url) de [text](url)
    text = re.sub(r'!?\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', text)
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| Expressions regulieres | Pattern matching pour parsing | 5/5 |
| Structure de document | Blocs vs inline | 4/5 |
| Echappement HTML | Securite et validite | 4/5 |
| Ordre de traitement | Priorite des regles | 4/5 |

---

### 5.3 Visualisation ASCII

**Structure d'un document Markdown :**

```
Document Markdown
|
+-- Block elements
|   |-- Headers (# to ######)
|   |-- Paragraphs
|   |-- Lists (ul, ol)
|   |-- Code blocks
|   |-- Tables
|   |-- Blockquotes
|   +-- Horizontal rules
|
+-- Inline elements
    |-- Bold (**text**)
    |-- Italic (*text*)
    |-- Code (`code`)
    |-- Links ([text](url))
    +-- Images (![alt](url))
```

**Ordre de processing :**

```
1. Code blocks    (preserve content)
2. Headers        (line level)
3. Lists          (multi-line)
4. Tables         (multi-line)
5. Blockquotes    (line level)
6. Paragraphs     (grouping)
7. Inline         (within blocks)
```

---

### 5.8 Mnemotechniques (MEME obligatoire)

#### MEME : "README Driven Development"

```
Developer: "I'll document later"
Narrator: "He did not document later"

The README.md is not just documentation.
It's a promise to your future self.
And to every developer who inherits your code.

# = Think big (h1)
## = Break it down (h2)
- List what matters
**Bold** the important stuff
*Italicize* the nuances
```

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | C.3.0-c |
| **Nom** | markdown_renderer |
| **Difficulte** | 4/10 |
| **Duree** | 40 min |
| **XP Base** | 60 |
| **Langage** | Python 3.14 |
| **Concepts cles** | Regex, parsing blocs/inline |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "C.3.0-c-markdown_renderer",
    "metadata": {
      "exercise_id": "C.3.0-c",
      "exercise_name": "markdown_renderer",
      "module": "C.3.0",
      "module_name": "Data Formats",
      "concept": "c",
      "concept_name": "Markdown Processing",
      "type": "code",
      "tier": 1,
      "phase": 0,
      "difficulty": 4,
      "language": "python",
      "language_version": "3.14"
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2 — L'excellence pedagogique ne se negocie pas*
