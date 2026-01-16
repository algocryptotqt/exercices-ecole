# Exercice 1.5.2-synth : Survey Corps DP Arsenal

**Module :**
1.5.2 — Sequence Dynamic Programming

**Concept :**
synth — Kadane, LCS, Edit Distance, LIS, Palindrome DP

**Difficulte :**
★★★★★★☆☆☆☆ (6/10)

**Type :**
complet

**Tiers :**
3 — Synthese (tous concepts a→e)

**Langage :**
Rust Edition 2024 ET C (C17)

**Prerequis :**
- 1.5.1-a : Concept de memoization
- 1.5.1-b : Tableaux et slices
- 0.3.x : Boucles imbriquees
- 0.4.x : Recursion basique

**Domaines :**
DP, Algo, Struct

**Duree estimee :**
120 min

**XP Base :**
150

**Complexite :**
T[3] O(n) a O(n*m) × S[3] O(n) a O(n*m)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `titans_kadane.rs` et `titans_kadane.c`
- `levi_squad_lcs.rs` et `levi_squad_lcs.c`
- `eren_transform.rs` et `eren_transform.c`
- `lis_freedom_path.rs` et `lis_freedom_path.c`
- `historia_palindrome.rs` et `historia_palindrome.c`

**Fonctions autorisees :**
- Rust : `std::cmp::{max, min}`, collections standard
- C : `stdlib.h` (malloc, free), `string.h` (strlen)

**Fonctions interdites :**
- Aucune bibliotheque de DP pre-implementee
- Pas de recursion sans memoization (sauf si explicitement autorise)

### 1.2 Consigne

**🎮 CONTEXTE : ATTACK ON TITAN — SURVEY CORPS MISSION PLANNING**

*"Nous sommes le Bataillon d'Exploration. Face aux Titans, nous n'avons qu'une arme : la STRATEGIE. Et la strategie, c'est de la programmation dynamique."* — Commandant Erwin Smith

Le Bataillon d'Exploration fait face a sa plus grande mission. Pour vaincre les Titans et atteindre la mer, tu dois maitriser 5 algorithmes de programmation dynamique qui representent les 5 piliers de la strategie militaire.

---

**🗡️ MISSION 1 : `titans_kadane` — Algorithme de Kadane**

*"Levi a tue 200 titans en un jour. Mais combien dans sa MEILLEURE sequence ?"*

Dans une mission, Levi traverse plusieurs zones. Chaque zone a un "score" : positif = titans tues, negatif = soldats perdus. Tu dois trouver la **sequence contigue** avec le score maximum.

**Ta mission :**
Ecrire une fonction `titans_kadane` qui trouve la somme maximale d'un sous-tableau contigu.

**Entree :**
- `kills` : Tableau d'entiers (positifs ou negatifs) representant le score de chaque zone

**Sortie :**
- Retourne la somme maximale d'un sous-tableau contigu
- Retourne 0 si le tableau est vide

**Contraintes :**
- Le tableau peut contenir des valeurs negatives
- Le tableau peut etre vide (retourner 0)
- Complexite attendue : O(n) temps, O(1) espace

**Exemples :**

| Appel | Retour | Explication |
|-------|--------|-------------|
| `titans_kadane([-2, 1, -3, 4, -1, 2, 1, -5, 4])` | `6` | Sous-tableau [4, -1, 2, 1] = 6 |
| `titans_kadane([1])` | `1` | Un seul element |
| `titans_kadane([-1, -2, -3])` | `-1` | Tous negatifs, prendre le moins pire |
| `titans_kadane([])` | `0` | Tableau vide |

---

**🛡️ MISSION 2 : `levi_squad_lcs` — Longest Common Subsequence**

*"L'escouade Levi et l'escouade Hanji doivent synchroniser leurs strategies."*

Deux escouades ont chacune un plan de bataille (sequence de manoeuvres). Tu dois trouver la **plus longue sous-sequence commune** entre leurs deux plans — les manoeuvres qu'elles peuvent executer ensemble.

**Ta mission :**
Ecrire une fonction `levi_squad_lcs` qui trouve la longueur de la LCS entre deux sequences.

**Entree :**
- `plan_a` : Chaine de caracteres (plan escouade Levi)
- `plan_b` : Chaine de caracteres (plan escouade Hanji)

**Sortie :**
- Retourne la longueur de la plus longue sous-sequence commune
- Retourne 0 si une des chaines est vide

**Contraintes :**
- Les chaines peuvent etre vides
- Sous-sequence ≠ sous-chaine (elements non forcement contigus)
- Complexite attendue : O(n*m) temps, O(n*m) espace (base) ou O(min(n,m)) (bonus)

**Exemples :**

| Appel | Retour | Explication |
|-------|--------|-------------|
| `levi_squad_lcs("ATTACK", "DEFEND")` | `2` | "AT" ou "AE" ou "DE" |
| `levi_squad_lcs("TITAN", "TITAN")` | `5` | Identiques |
| `levi_squad_lcs("ABC", "DEF")` | `0` | Aucun caractere commun |
| `levi_squad_lcs("", "WALL")` | `0` | Chaine vide |

---

**⚡ MISSION 3 : `eren_transform` — Edit Distance (Levenshtein)**

*"Combien de transformations pour passer d'EREN a TITAN ?"*

Eren peut se transformer. Chaque transformation a un cout. Tu dois calculer le **nombre minimum d'operations** (insertion, suppression, substitution) pour transformer une chaine en une autre.

**Ta mission :**
Ecrire une fonction `eren_transform` qui calcule la distance d'edition entre deux chaines.

**Entree :**
- `source` : Chaine source (forme de depart)
- `target` : Chaine cible (forme d'arrivee)

**Sortie :**
- Retourne le nombre minimum d'operations pour transformer source en target
- Chaque operation (insert, delete, replace) coute 1

**Contraintes :**
- Les chaines peuvent etre vides (distance = longueur de l'autre)
- Complexite attendue : O(n*m) temps, O(n*m) espace

**Exemples :**

| Appel | Retour | Explication |
|-------|--------|-------------|
| `eren_transform("EREN", "TITAN")` | `5` | E→T, R→I, E→T, N→A, +N |
| `eren_transform("WALL", "WALLS")` | `1` | +S |
| `eren_transform("MARIA", "ROSE")` | `5` | Toutes les lettres differentes |
| `eren_transform("", "AOT")` | `3` | 3 insertions |

---

**🏔️ MISSION 4 : `lis_freedom_path` — Longest Increasing Subsequence**

*"Le chemin vers la liberte est toujours ASCENDANT."*

Pour atteindre la mer, tu dois suivre un chemin ou chaque point est a une altitude superieure au precedent. Tu dois trouver le **plus long chemin strictement croissant**.

**Ta mission :**
Ecrire une fonction `lis_freedom_path` qui trouve la longueur de la LIS.

**Entree :**
- `altitudes` : Tableau d'entiers representant les altitudes

**Sortie :**
- Retourne la longueur de la plus longue sous-sequence strictement croissante

**Contraintes :**
- Le tableau peut etre vide (retourner 0)
- Strictement croissant (pas d'egalite)
- Complexite attendue : O(n log n) temps (bonus) ou O(n^2) (base)

**Exemples :**

| Appel | Retour | Explication |
|-------|--------|-------------|
| `lis_freedom_path([10, 9, 2, 5, 3, 7, 101, 18])` | `4` | [2, 3, 7, 18] ou [2, 5, 7, 101] |
| `lis_freedom_path([0, 1, 0, 3, 2, 3])` | `4` | [0, 1, 2, 3] |
| `lis_freedom_path([7, 7, 7, 7])` | `1` | Pas strictement croissant |
| `lis_freedom_path([])` | `0` | Tableau vide |

---

**👑 MISSION 5 : `historia_palindrome` — Longest Palindromic Subsequence**

*"Les secrets de la famille Reiss se lisent dans les deux sens."*

Les memoires royales sont encodees en palindromes. Tu dois trouver la **plus longue sous-sequence palindromique** dans un texte ancien.

**Ta mission :**
Ecrire une fonction `historia_palindrome` qui trouve la longueur du plus long palindrome (sous-sequence).

**Entree :**
- `secret` : Chaine de caracteres contenant le message encode

**Sortie :**
- Retourne la longueur de la plus longue sous-sequence palindromique

**Contraintes :**
- Sous-sequence, pas sous-chaine
- La chaine peut etre vide (retourner 0)
- Complexite attendue : O(n^2) temps, O(n^2) espace

**Exemples :**

| Appel | Retour | Explication |
|-------|--------|-------------|
| `historia_palindrome("BBABCBAB")` | `7` | "BABCBAB" |
| `historia_palindrome("TITAN")` | `3` | "TIT" ou "TNT" ou "TAT" |
| `historia_palindrome("ABCDEF")` | `1` | Un seul caractere |
| `historia_palindrome("RACECAR")` | `7` | Deja un palindrome |

---

### 1.3 Prototypes

**Rust (Edition 2024) :**

```rust
// titans_kadane.rs
pub fn titans_kadane(kills: &[i32]) -> i32;

// levi_squad_lcs.rs
pub fn levi_squad_lcs(plan_a: &str, plan_b: &str) -> usize;

// eren_transform.rs
pub fn eren_transform(source: &str, target: &str) -> usize;

// lis_freedom_path.rs
pub fn lis_freedom_path(altitudes: &[i32]) -> usize;

// historia_palindrome.rs
pub fn historia_palindrome(secret: &str) -> usize;
```

**C (C17) :**

```c
// titans_kadane.c
int titans_kadane(int *kills, int size);

// levi_squad_lcs.c
int levi_squad_lcs(const char *plan_a, const char *plan_b);

// eren_transform.c
int eren_transform(const char *source, const char *target);

// lis_freedom_path.c
int lis_freedom_path(int *altitudes, int size);

// historia_palindrome.c
int historia_palindrome(const char *secret);
```

---

### 1.2.2 Enonce Academique

**Contexte :**
Cet exercice de synthese couvre 5 algorithmes fondamentaux de programmation dynamique sur sequences :

1. **Algorithme de Kadane** : Trouve la somme maximale d'un sous-tableau contigu en O(n).
2. **Longest Common Subsequence (LCS)** : Trouve la plus longue sous-sequence commune entre deux chaines.
3. **Edit Distance (Levenshtein)** : Calcule le nombre minimum d'operations pour transformer une chaine en une autre.
4. **Longest Increasing Subsequence (LIS)** : Trouve la plus longue sous-sequence strictement croissante.
5. **Longest Palindromic Subsequence** : Trouve la plus longue sous-sequence qui est un palindrome.

Ces algorithmes sont les piliers de la DP sequentielle et sont utilises dans de nombreux domaines : bioinformatique, traitement de texte, compression, etc.

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Origine des Algorithmes

- **Kadane (1984)** : Jay Kadane a resolu le probleme du sous-tableau maximum en O(n), alors que les solutions precedentes etaient en O(n^2) ou O(n^3).

- **LCS** : Utilise dans `diff` (Unix), le versionning (Git), et l'alignement de sequences ADN.

- **Edit Distance** : Invente par Vladimir Levenshtein en 1965 pour la theorie de l'information. Utilise par les correcteurs orthographiques et la bioinformatique.

- **LIS** : Lie au theoreme d'Erdos-Szekeres et aux permutations de Young.

- **Palindrome** : La recherche de palindromes est liee a la compression de donnees et a la genetique (sequences reperees inversees).

### 2.2 Le Pattern DP Commun

Tous ces algorithmes partagent la meme structure :
1. **Definir l'etat** : `dp[i]` ou `dp[i][j]`
2. **Relation de recurrence** : Comment calculer un etat a partir des precedents
3. **Cas de base** : Initialisation
4. **Ordre de remplissage** : Gauche-droite, bas-haut, diagonale...
5. **Extraction de la reponse** : Souvent `dp[n]` ou `max(dp)`

---

### SECTION 2.5 : "DANS LA VRAIE VIE"

**Qui utilise ces algorithmes ?**

| Metier | Algorithme | Cas d'usage |
|--------|------------|-------------|
| **Bioinformaticien** | LCS, Edit Distance | Alignement de sequences ADN/proteines (BLAST, FASTA) |
| **Developpeur Git** | LCS | Calcul des diffs entre fichiers |
| **Ingenieur NLP** | Edit Distance | Correction orthographique, suggestions de mots |
| **Quant/Trader** | Kadane | Trouver la meilleure periode d'achat/vente |
| **Ingenieur Compression** | LIS, Palindrome | Algorithmes de compression (LZ77, etc.) |
| **Game Designer** | LIS | Pathfinding avec contraintes croissantes |

**Exemple concret :**
```
Git diff utilise LCS pour trouver les lignes communes entre deux versions d'un fichier.
Les lignes non communes sont marquees + (ajoutees) ou - (supprimees).
```

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

**Rust :**
```bash
$ ls
titans_kadane.rs  levi_squad_lcs.rs  eren_transform.rs  lis_freedom_path.rs  historia_palindrome.rs  main.rs

$ rustc --edition 2024 -o test main.rs titans_kadane.rs levi_squad_lcs.rs eren_transform.rs lis_freedom_path.rs historia_palindrome.rs

$ ./test
[KADANE] titans_kadane([-2, 1, -3, 4, -1, 2, 1, -5, 4]) = 6 ... OK
[LCS] levi_squad_lcs("ATTACK", "DEFEND") = 2 ... OK
[EDIT] eren_transform("EREN", "TITAN") = 5 ... OK
[LIS] lis_freedom_path([10, 9, 2, 5, 3, 7, 101, 18]) = 4 ... OK
[PALINDROME] historia_palindrome("BBABCBAB") = 7 ... OK
Tous les tests passent! Shinzou wo Sasageyo!
```

**C :**
```bash
$ ls
titans_kadane.c  levi_squad_lcs.c  eren_transform.c  lis_freedom_path.c  historia_palindrome.c  main.c

$ gcc -Wall -Wextra -Werror -std=c17 -o test *.c

$ ./test
[KADANE] titans_kadane([-2, 1, -3, 4, -1, 2, 1, -5, 4]) = 6 ... OK
[LCS] levi_squad_lcs("ATTACK", "DEFEND") = 2 ... OK
[EDIT] eren_transform("EREN", "TITAN") = 5 ... OK
[LIS] lis_freedom_path([10, 9, 2, 5, 3, 7, 101, 18]) = 4 ... OK
[PALINDROME] historia_palindrome("BBABCBAB") = 7 ... OK
Tous les tests passent! Shinzou wo Sasageyo!
```

---

### 3.1 🔥 BONUS AVANCE (OPTIONNEL)

**Difficulte Bonus :**
★★★★★★★★☆☆ (8/10)

**Recompense :**
XP ×3

**Time Complexity attendue :**
- LCS : O(n*m) temps, O(min(n,m)) espace
- LIS : O(n log n) temps

**Space Complexity attendue :**
O(n) pour tous

**Domaines Bonus :**
`Algo, Optim`

#### 3.1.1 Consigne Bonus

**🔥 OPERATION RUMBLING — OPTIMISATION MEMOIRE**

*"Les ressources sont limitees. Chaque octet compte."*

Le Commandant Erwin exige des algorithmes plus efficaces en memoire :

**Bonus 1 : LCS en O(min(n,m)) espace**
Au lieu d'une matrice n×m, utilise seulement 2 lignes (ou 1 ligne + variable).

**Bonus 2 : LIS en O(n log n) temps**
Utilise la recherche binaire pour optimiser la complexite.

**Bonus 3 : Reconstruction**
En plus de la longueur, retourne la sequence elle-meme.

**Ta mission :**

```rust
// Bonus LCS - espace optimise
pub fn levi_squad_lcs_optimized(plan_a: &str, plan_b: &str) -> usize;

// Bonus LIS - temps optimise
pub fn lis_freedom_path_fast(altitudes: &[i32]) -> usize;

// Bonus reconstruction
pub fn titans_kadane_indices(kills: &[i32]) -> (i32, usize, usize);
pub fn lis_freedom_path_sequence(altitudes: &[i32]) -> Vec<i32>;
```

**Contraintes :**
```
┌─────────────────────────────────────────┐
│  LCS optimise : O(min(n,m)) espace      │
│  LIS optimise : O(n log n) temps        │
│  Reconstruction : memes complexites     │
└─────────────────────────────────────────┘
```

#### 3.1.2 Prototype Bonus

**Rust :**
```rust
pub fn levi_squad_lcs_optimized(plan_a: &str, plan_b: &str) -> usize;
pub fn lis_freedom_path_fast(altitudes: &[i32]) -> usize;
pub fn titans_kadane_indices(kills: &[i32]) -> (i32, usize, usize);
pub fn lis_freedom_path_sequence(altitudes: &[i32]) -> Vec<i32>;
```

**C :**
```c
int levi_squad_lcs_optimized(const char *plan_a, const char *plan_b);
int lis_freedom_path_fast(int *altitudes, int size);
typedef struct { int sum; int start; int end; } KadaneResult;
KadaneResult titans_kadane_indices(int *kills, int size);
int *lis_freedom_path_sequence(int *altitudes, int size, int *out_len);
```

#### 3.1.3 Ce qui change par rapport a l'exercice de base

| Aspect | Base | Bonus |
|--------|------|-------|
| LCS espace | O(n*m) | O(min(n,m)) |
| LIS temps | O(n^2) | O(n log n) |
| Retour | Longueur | Longueur + sequence |
| Difficulte | 6/10 | 8/10 |

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test | Input | Expected | Points | Type |
|------|-------|----------|--------|------|
| kadane_basic | `[-2, 1, -3, 4, -1, 2, 1, -5, 4]` | `6` | 5 | Base |
| kadane_single | `[1]` | `1` | 2 | Edge |
| kadane_all_neg | `[-1, -2, -3]` | `-1` | 5 | Trap |
| kadane_empty | `[]` | `0` | 3 | Edge |
| kadane_all_pos | `[1, 2, 3, 4]` | `10` | 3 | Base |
| lcs_basic | `"ATTACK", "DEFEND"` | `2` | 5 | Base |
| lcs_identical | `"TITAN", "TITAN"` | `5` | 3 | Edge |
| lcs_none | `"ABC", "DEF"` | `0` | 3 | Edge |
| lcs_empty | `"", "WALL"` | `0` | 3 | Edge |
| edit_basic | `"EREN", "TITAN"` | `5` | 5 | Base |
| edit_insert | `"WALL", "WALLS"` | `1` | 3 | Base |
| edit_empty | `"", "AOT"` | `3` | 3 | Edge |
| edit_same | `"LEVI", "LEVI"` | `0` | 3 | Edge |
| lis_basic | `[10, 9, 2, 5, 3, 7, 101, 18]` | `4` | 5 | Base |
| lis_all_same | `[7, 7, 7, 7]` | `1` | 3 | Trap |
| lis_empty | `[]` | `0` | 3 | Edge |
| lis_decreasing | `[5, 4, 3, 2, 1]` | `1` | 3 | Edge |
| palindrome_basic | `"BBABCBAB"` | `7` | 5 | Base |
| palindrome_single | `"A"` | `1` | 2 | Edge |
| palindrome_none | `"ABCDEF"` | `1` | 3 | Edge |
| palindrome_full | `"RACECAR"` | `7` | 3 | Base |

### 4.2 main.c de test

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Prototypes
int titans_kadane(int *kills, int size);
int levi_squad_lcs(const char *plan_a, const char *plan_b);
int eren_transform(const char *source, const char *target);
int lis_freedom_path(int *altitudes, int size);
int historia_palindrome(const char *secret);

#define TEST(name, expr, expected) do { \
    int result = (expr); \
    if (result == (expected)) { \
        printf("[%s] OK\n", name); \
    } else { \
        printf("[%s] FAIL: got %d, expected %d\n", name, result, expected); \
        fails++; \
    } \
} while(0)

int main(void)
{
    int fails = 0;

    // Kadane tests
    int k1[] = {-2, 1, -3, 4, -1, 2, 1, -5, 4};
    TEST("kadane_basic", titans_kadane(k1, 9), 6);

    int k2[] = {1};
    TEST("kadane_single", titans_kadane(k2, 1), 1);

    int k3[] = {-1, -2, -3};
    TEST("kadane_all_neg", titans_kadane(k3, 3), -1);

    TEST("kadane_empty", titans_kadane(NULL, 0), 0);

    // LCS tests
    TEST("lcs_basic", levi_squad_lcs("ATTACK", "DEFEND"), 2);
    TEST("lcs_identical", levi_squad_lcs("TITAN", "TITAN"), 5);
    TEST("lcs_none", levi_squad_lcs("ABC", "DEF"), 0);
    TEST("lcs_empty", levi_squad_lcs("", "WALL"), 0);

    // Edit Distance tests
    TEST("edit_basic", eren_transform("EREN", "TITAN"), 5);
    TEST("edit_insert", eren_transform("WALL", "WALLS"), 1);
    TEST("edit_empty", eren_transform("", "AOT"), 3);
    TEST("edit_same", eren_transform("LEVI", "LEVI"), 0);

    // LIS tests
    int l1[] = {10, 9, 2, 5, 3, 7, 101, 18};
    TEST("lis_basic", lis_freedom_path(l1, 8), 4);

    int l2[] = {7, 7, 7, 7};
    TEST("lis_all_same", lis_freedom_path(l2, 4), 1);

    TEST("lis_empty", lis_freedom_path(NULL, 0), 0);

    int l3[] = {5, 4, 3, 2, 1};
    TEST("lis_decreasing", lis_freedom_path(l3, 5), 1);

    // Palindrome tests
    TEST("palindrome_basic", historia_palindrome("BBABCBAB"), 7);
    TEST("palindrome_single", historia_palindrome("A"), 1);
    TEST("palindrome_none", historia_palindrome("ABCDEF"), 1);
    TEST("palindrome_full", historia_palindrome("RACECAR"), 7);

    printf("\n%s\n", fails == 0 ? "Tous les tests passent! Shinzou wo Sasageyo!" : "Des tests ont echoue.");
    return fails;
}
```

### 4.3 Solution de reference

**Rust :**

```rust
// titans_kadane.rs
pub fn titans_kadane(kills: &[i32]) -> i32 {
    if kills.is_empty() {
        return 0;
    }

    let mut max_ending_here = kills[0];
    let mut max_so_far = kills[0];

    for &kill in &kills[1..] {
        max_ending_here = std::cmp::max(kill, max_ending_here + kill);
        max_so_far = std::cmp::max(max_so_far, max_ending_here);
    }

    max_so_far
}

// levi_squad_lcs.rs
pub fn levi_squad_lcs(plan_a: &str, plan_b: &str) -> usize {
    let a: Vec<char> = plan_a.chars().collect();
    let b: Vec<char> = plan_b.chars().collect();
    let n = a.len();
    let m = b.len();

    if n == 0 || m == 0 {
        return 0;
    }

    let mut dp = vec![vec![0usize; m + 1]; n + 1];

    for i in 1..=n {
        for j in 1..=m {
            if a[i - 1] == b[j - 1] {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = std::cmp::max(dp[i - 1][j], dp[i][j - 1]);
            }
        }
    }

    dp[n][m]
}

// eren_transform.rs
pub fn eren_transform(source: &str, target: &str) -> usize {
    let s: Vec<char> = source.chars().collect();
    let t: Vec<char> = target.chars().collect();
    let n = s.len();
    let m = t.len();

    let mut dp = vec![vec![0usize; m + 1]; n + 1];

    // Base cases
    for i in 0..=n {
        dp[i][0] = i;
    }
    for j in 0..=m {
        dp[0][j] = j;
    }

    for i in 1..=n {
        for j in 1..=m {
            if s[i - 1] == t[j - 1] {
                dp[i][j] = dp[i - 1][j - 1];
            } else {
                dp[i][j] = 1 + std::cmp::min(
                    dp[i - 1][j - 1], // replace
                    std::cmp::min(dp[i - 1][j], dp[i][j - 1]) // delete, insert
                );
            }
        }
    }

    dp[n][m]
}

// lis_freedom_path.rs
pub fn lis_freedom_path(altitudes: &[i32]) -> usize {
    if altitudes.is_empty() {
        return 0;
    }

    let n = altitudes.len();
    let mut dp = vec![1usize; n];

    for i in 1..n {
        for j in 0..i {
            if altitudes[j] < altitudes[i] {
                dp[i] = std::cmp::max(dp[i], dp[j] + 1);
            }
        }
    }

    *dp.iter().max().unwrap()
}

// historia_palindrome.rs
pub fn historia_palindrome(secret: &str) -> usize {
    let s: Vec<char> = secret.chars().collect();
    let n = s.len();

    if n == 0 {
        return 0;
    }

    let mut dp = vec![vec![0usize; n]; n];

    // Base case: single characters
    for i in 0..n {
        dp[i][i] = 1;
    }

    // Fill for lengths 2 to n
    for len in 2..=n {
        for i in 0..=n - len {
            let j = i + len - 1;
            if s[i] == s[j] {
                dp[i][j] = dp[i + 1][j - 1] + 2;
            } else {
                dp[i][j] = std::cmp::max(dp[i + 1][j], dp[i][j - 1]);
            }
        }
    }

    dp[0][n - 1]
}
```

**C :**

```c
// titans_kadane.c
#include <stdlib.h>

int titans_kadane(int *kills, int size)
{
    if (kills == NULL || size <= 0)
        return 0;

    int max_ending_here = kills[0];
    int max_so_far = kills[0];

    for (int i = 1; i < size; i++)
    {
        if (kills[i] > max_ending_here + kills[i])
            max_ending_here = kills[i];
        else
            max_ending_here = max_ending_here + kills[i];

        if (max_ending_here > max_so_far)
            max_so_far = max_ending_here;
    }

    return max_so_far;
}

// levi_squad_lcs.c
#include <stdlib.h>
#include <string.h>

int levi_squad_lcs(const char *plan_a, const char *plan_b)
{
    if (plan_a == NULL || plan_b == NULL)
        return 0;

    int n = strlen(plan_a);
    int m = strlen(plan_b);

    if (n == 0 || m == 0)
        return 0;

    int **dp = malloc((n + 1) * sizeof(int *));
    for (int i = 0; i <= n; i++)
    {
        dp[i] = calloc(m + 1, sizeof(int));
    }

    for (int i = 1; i <= n; i++)
    {
        for (int j = 1; j <= m; j++)
        {
            if (plan_a[i - 1] == plan_b[j - 1])
                dp[i][j] = dp[i - 1][j - 1] + 1;
            else
                dp[i][j] = (dp[i - 1][j] > dp[i][j - 1]) ? dp[i - 1][j] : dp[i][j - 1];
        }
    }

    int result = dp[n][m];

    for (int i = 0; i <= n; i++)
        free(dp[i]);
    free(dp);

    return result;
}

// eren_transform.c
#include <stdlib.h>
#include <string.h>

static int min3(int a, int b, int c)
{
    int min = a;
    if (b < min) min = b;
    if (c < min) min = c;
    return min;
}

int eren_transform(const char *source, const char *target)
{
    if (source == NULL) source = "";
    if (target == NULL) target = "";

    int n = strlen(source);
    int m = strlen(target);

    int **dp = malloc((n + 1) * sizeof(int *));
    for (int i = 0; i <= n; i++)
        dp[i] = malloc((m + 1) * sizeof(int));

    for (int i = 0; i <= n; i++)
        dp[i][0] = i;
    for (int j = 0; j <= m; j++)
        dp[0][j] = j;

    for (int i = 1; i <= n; i++)
    {
        for (int j = 1; j <= m; j++)
        {
            if (source[i - 1] == target[j - 1])
                dp[i][j] = dp[i - 1][j - 1];
            else
                dp[i][j] = 1 + min3(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
        }
    }

    int result = dp[n][m];

    for (int i = 0; i <= n; i++)
        free(dp[i]);
    free(dp);

    return result;
}

// lis_freedom_path.c
#include <stdlib.h>

int lis_freedom_path(int *altitudes, int size)
{
    if (altitudes == NULL || size <= 0)
        return 0;

    int *dp = malloc(size * sizeof(int));
    for (int i = 0; i < size; i++)
        dp[i] = 1;

    for (int i = 1; i < size; i++)
    {
        for (int j = 0; j < i; j++)
        {
            if (altitudes[j] < altitudes[i] && dp[j] + 1 > dp[i])
                dp[i] = dp[j] + 1;
        }
    }

    int max = dp[0];
    for (int i = 1; i < size; i++)
    {
        if (dp[i] > max)
            max = dp[i];
    }

    free(dp);
    return max;
}

// historia_palindrome.c
#include <stdlib.h>
#include <string.h>

int historia_palindrome(const char *secret)
{
    if (secret == NULL || *secret == '\0')
        return 0;

    int n = strlen(secret);

    int **dp = malloc(n * sizeof(int *));
    for (int i = 0; i < n; i++)
    {
        dp[i] = calloc(n, sizeof(int));
        dp[i][i] = 1;
    }

    for (int len = 2; len <= n; len++)
    {
        for (int i = 0; i <= n - len; i++)
        {
            int j = i + len - 1;
            if (secret[i] == secret[j])
                dp[i][j] = dp[i + 1][j - 1] + 2;
            else
                dp[i][j] = (dp[i + 1][j] > dp[i][j - 1]) ? dp[i + 1][j] : dp[i][j - 1];
        }
    }

    int result = dp[0][n - 1];

    for (int i = 0; i < n; i++)
        free(dp[i]);
    free(dp);

    return result;
}
```

### 4.4 Solutions alternatives acceptees

**Alternative 1 : Kadane avec indices (tracking)**

```c
int titans_kadane_v2(int *kills, int size)
{
    if (!kills || size <= 0) return 0;

    int max_sum = kills[0];
    int current_sum = kills[0];

    for (int i = 1; i < size; i++)
    {
        current_sum = (kills[i] > current_sum + kills[i]) ? kills[i] : current_sum + kills[i];
        max_sum = (current_sum > max_sum) ? current_sum : max_sum;
    }

    return max_sum;
}
```

**Alternative 2 : LIS avec recherche binaire O(n log n)**

```c
#include <stdlib.h>

int lower_bound(int *arr, int len, int target)
{
    int lo = 0, hi = len;
    while (lo < hi)
    {
        int mid = (lo + hi) / 2;
        if (arr[mid] < target)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

int lis_freedom_path_fast(int *altitudes, int size)
{
    if (!altitudes || size <= 0) return 0;

    int *tails = malloc(size * sizeof(int));
    int len = 0;

    for (int i = 0; i < size; i++)
    {
        int pos = lower_bound(tails, len, altitudes[i]);
        tails[pos] = altitudes[i];
        if (pos == len) len++;
    }

    free(tails);
    return len;
}
```

### 4.5 Solutions refusees (avec explications)

**Refusee 1 : Kadane qui retourne 0 pour tous negatifs**

```c
// REFUSE : Ne gere pas le cas "tous negatifs"
int titans_kadane_wrong(int *kills, int size)
{
    if (!kills || size <= 0) return 0;

    int max_sum = 0;  // ERREUR : devrait etre kills[0]
    int current = 0;

    for (int i = 0; i < size; i++)
    {
        current = (current + kills[i] > 0) ? current + kills[i] : 0;  // ERREUR
        if (current > max_sum) max_sum = current;
    }

    return max_sum;  // Retourne 0 pour [-1, -2, -3] au lieu de -1
}
```
**Pourquoi refuse :** L'algorithme doit retourner le moins negatif, pas 0.

**Refusee 2 : LCS recursif sans memoization**

```c
// REFUSE : Complexite exponentielle O(2^n)
int lcs_recursive_slow(const char *a, const char *b, int i, int j)
{
    if (i == 0 || j == 0) return 0;
    if (a[i-1] == b[j-1])
        return 1 + lcs_recursive_slow(a, b, i-1, j-1);
    return max(lcs_recursive_slow(a, b, i-1, j), lcs_recursive_slow(a, b, i, j-1));
}
```
**Pourquoi refuse :** Timeout sur grandes entrees. La memoization est requise.

**Refusee 3 : Edit Distance sans cas de base**

```c
// REFUSE : Pas d'initialisation des bords
int eren_transform_wrong(const char *source, const char *target)
{
    int n = strlen(source);
    int m = strlen(target);
    int **dp = malloc((n+1) * sizeof(int *));
    for (int i = 0; i <= n; i++)
        dp[i] = calloc(m+1, sizeof(int));  // Tout a 0, ERREUR

    // dp[i][0] devrait etre i, dp[0][j] devrait etre j
    // ...
}
```
**Pourquoi refuse :** Les suppressions et insertions initiales ne sont pas comptees.

### 4.6 Solution bonus de reference (COMPLETE)

**Rust :**

```rust
// Bonus : LCS en O(min(n,m)) espace
pub fn levi_squad_lcs_optimized(plan_a: &str, plan_b: &str) -> usize {
    let a: Vec<char> = plan_a.chars().collect();
    let b: Vec<char> = plan_b.chars().collect();

    // Ensure b is the shorter one
    let (a, b) = if a.len() < b.len() { (b, a) } else { (a, b) };
    let n = a.len();
    let m = b.len();

    if m == 0 {
        return 0;
    }

    let mut prev = vec![0usize; m + 1];
    let mut curr = vec![0usize; m + 1];

    for i in 1..=n {
        for j in 1..=m {
            if a[i - 1] == b[j - 1] {
                curr[j] = prev[j - 1] + 1;
            } else {
                curr[j] = std::cmp::max(prev[j], curr[j - 1]);
            }
        }
        std::mem::swap(&mut prev, &mut curr);
        curr.fill(0);
    }

    prev[m]
}

// Bonus : LIS en O(n log n)
pub fn lis_freedom_path_fast(altitudes: &[i32]) -> usize {
    if altitudes.is_empty() {
        return 0;
    }

    let mut tails: Vec<i32> = Vec::new();

    for &num in altitudes {
        let pos = tails.partition_point(|&x| x < num);
        if pos == tails.len() {
            tails.push(num);
        } else {
            tails[pos] = num;
        }
    }

    tails.len()
}

// Bonus : Kadane avec indices
pub fn titans_kadane_indices(kills: &[i32]) -> (i32, usize, usize) {
    if kills.is_empty() {
        return (0, 0, 0);
    }

    let mut max_sum = kills[0];
    let mut current_sum = kills[0];
    let mut start = 0;
    let mut end = 0;
    let mut temp_start = 0;

    for i in 1..kills.len() {
        if kills[i] > current_sum + kills[i] {
            current_sum = kills[i];
            temp_start = i;
        } else {
            current_sum += kills[i];
        }

        if current_sum > max_sum {
            max_sum = current_sum;
            start = temp_start;
            end = i;
        }
    }

    (max_sum, start, end)
}

// Bonus : LIS avec reconstruction
pub fn lis_freedom_path_sequence(altitudes: &[i32]) -> Vec<i32> {
    if altitudes.is_empty() {
        return Vec::new();
    }

    let n = altitudes.len();
    let mut dp = vec![1usize; n];
    let mut parent = vec![usize::MAX; n];

    for i in 1..n {
        for j in 0..i {
            if altitudes[j] < altitudes[i] && dp[j] + 1 > dp[i] {
                dp[i] = dp[j] + 1;
                parent[i] = j;
            }
        }
    }

    // Find the index with max LIS
    let mut max_idx = 0;
    for i in 1..n {
        if dp[i] > dp[max_idx] {
            max_idx = i;
        }
    }

    // Reconstruct
    let mut result = Vec::new();
    let mut idx = max_idx;
    while idx != usize::MAX {
        result.push(altitudes[idx]);
        idx = parent[idx];
    }
    result.reverse();

    result
}
```

### 4.7 Solutions alternatives bonus (COMPLETES)

**Alternative : LCS avec une seule ligne**

```rust
pub fn levi_squad_lcs_single_row(plan_a: &str, plan_b: &str) -> usize {
    let a: Vec<char> = plan_a.chars().collect();
    let b: Vec<char> = plan_b.chars().collect();
    let n = a.len();
    let m = b.len();

    if n == 0 || m == 0 {
        return 0;
    }

    let mut dp = vec![0usize; m + 1];

    for i in 1..=n {
        let mut prev = 0;
        for j in 1..=m {
            let temp = dp[j];
            if a[i - 1] == b[j - 1] {
                dp[j] = prev + 1;
            } else {
                dp[j] = std::cmp::max(dp[j], dp[j - 1]);
            }
            prev = temp;
        }
    }

    dp[m]
}
```

### 4.8 Solutions refusees bonus (COMPLETES)

**Refusee : LIS O(n log n) avec mauvais lower_bound**

```rust
// REFUSE : Utilise upper_bound au lieu de lower_bound
pub fn lis_wrong(altitudes: &[i32]) -> usize {
    let mut tails: Vec<i32> = Vec::new();

    for &num in altitudes {
        // ERREUR : <= au lieu de <, compte les egalites
        let pos = tails.partition_point(|&x| x <= num);  // MAUVAIS
        if pos == tails.len() {
            tails.push(num);
        } else {
            tails[pos] = num;
        }
    }

    tails.len()
}
```
**Pourquoi refuse :** Ne trouve pas la LIS *strictement* croissante.

### 4.9 spec.json (ENGINE v22.1 — FORMAT STRICT)

```json
{
  "name": "survey_corps_dp_arsenal",
  "language": ["rust", "c"],
  "type": "complet",
  "tier": 3,
  "tier_info": "Synthese (concepts a→e)",
  "tags": ["dp", "kadane", "lcs", "edit_distance", "lis", "palindrome", "phase1", "aot"],
  "passing_score": 70,

  "functions": [
    {
      "name": "titans_kadane",
      "prototype_rust": "pub fn titans_kadane(kills: &[i32]) -> i32",
      "prototype_c": "int titans_kadane(int *kills, int size)",
      "return_type": "int"
    },
    {
      "name": "levi_squad_lcs",
      "prototype_rust": "pub fn levi_squad_lcs(plan_a: &str, plan_b: &str) -> usize",
      "prototype_c": "int levi_squad_lcs(const char *plan_a, const char *plan_b)",
      "return_type": "int"
    },
    {
      "name": "eren_transform",
      "prototype_rust": "pub fn eren_transform(source: &str, target: &str) -> usize",
      "prototype_c": "int eren_transform(const char *source, const char *target)",
      "return_type": "int"
    },
    {
      "name": "lis_freedom_path",
      "prototype_rust": "pub fn lis_freedom_path(altitudes: &[i32]) -> usize",
      "prototype_c": "int lis_freedom_path(int *altitudes, int size)",
      "return_type": "int"
    },
    {
      "name": "historia_palindrome",
      "prototype_rust": "pub fn historia_palindrome(secret: &str) -> usize",
      "prototype_c": "int historia_palindrome(const char *secret)",
      "return_type": "int"
    }
  ],

  "driver": {
    "reference_rust": "pub fn ref_titans_kadane(kills: &[i32]) -> i32 { if kills.is_empty() { return 0; } let mut meh = kills[0]; let mut msf = kills[0]; for &k in &kills[1..] { meh = std::cmp::max(k, meh + k); msf = std::cmp::max(msf, meh); } msf }",
    "reference_c": "int ref_titans_kadane(int *kills, int size) { if (!kills || size <= 0) return 0; int meh = kills[0], msf = kills[0]; for (int i = 1; i < size; i++) { meh = (kills[i] > meh + kills[i]) ? kills[i] : meh + kills[i]; msf = (meh > msf) ? meh : msf; } return msf; }",

    "edge_cases": [
      {
        "name": "kadane_basic",
        "function": "titans_kadane",
        "args_rust": "[[-2, 1, -3, 4, -1, 2, 1, -5, 4]]",
        "args_c": "{-2, 1, -3, 4, -1, 2, 1, -5, 4}, 9",
        "expected": 6
      },
      {
        "name": "kadane_all_negative",
        "function": "titans_kadane",
        "args_rust": "[[-5, -3, -8, -1, -2]]",
        "args_c": "{-5, -3, -8, -1, -2}, 5",
        "expected": -1,
        "is_trap": true,
        "trap_explanation": "Tous negatifs : doit retourner -1, pas 0"
      },
      {
        "name": "kadane_empty",
        "function": "titans_kadane",
        "args_rust": "[[]]",
        "args_c": "NULL, 0",
        "expected": 0,
        "is_trap": true,
        "trap_explanation": "Tableau vide doit retourner 0"
      },
      {
        "name": "lcs_basic",
        "function": "levi_squad_lcs",
        "args": ["ATTACK", "DEFEND"],
        "expected": 2
      },
      {
        "name": "lcs_identical",
        "function": "levi_squad_lcs",
        "args": ["TITAN", "TITAN"],
        "expected": 5
      },
      {
        "name": "lcs_empty",
        "function": "levi_squad_lcs",
        "args": ["", "WALL"],
        "expected": 0,
        "is_trap": true,
        "trap_explanation": "Chaine vide = LCS 0"
      },
      {
        "name": "edit_basic",
        "function": "eren_transform",
        "args": ["EREN", "TITAN"],
        "expected": 5
      },
      {
        "name": "edit_same",
        "function": "eren_transform",
        "args": ["LEVI", "LEVI"],
        "expected": 0
      },
      {
        "name": "lis_basic",
        "function": "lis_freedom_path",
        "args_rust": "[[10, 9, 2, 5, 3, 7, 101, 18]]",
        "args_c": "{10, 9, 2, 5, 3, 7, 101, 18}, 8",
        "expected": 4
      },
      {
        "name": "lis_all_same",
        "function": "lis_freedom_path",
        "args_rust": "[[7, 7, 7, 7]]",
        "args_c": "{7, 7, 7, 7}, 4",
        "expected": 1,
        "is_trap": true,
        "trap_explanation": "STRICTEMENT croissant, pas d'egalite"
      },
      {
        "name": "palindrome_basic",
        "function": "historia_palindrome",
        "args": ["BBABCBAB"],
        "expected": 7
      },
      {
        "name": "palindrome_single",
        "function": "historia_palindrome",
        "args": ["A"],
        "expected": 1
      }
    ],

    "fuzzing": {
      "enabled": true,
      "iterations": 500,
      "generators": [
        {
          "function": "titans_kadane",
          "type": "array_int",
          "param_index": 0,
          "params": {
            "min_len": 0,
            "max_len": 100,
            "min_val": -1000,
            "max_val": 1000
          }
        },
        {
          "function": "levi_squad_lcs",
          "type": "string",
          "param_index": 0,
          "params": {
            "min_len": 0,
            "max_len": 50,
            "charset": "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
          }
        }
      ]
    }
  },

  "norm": {
    "allowed_functions_rust": ["std::cmp::max", "std::cmp::min", "Vec::new", "Vec::push"],
    "allowed_functions_c": ["malloc", "free", "strlen", "calloc"],
    "forbidden_functions": [],
    "check_memory": true,
    "blocking": true
  }
}
```

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Kadane avec mauvaise initialisation**

```c
/* Mutant A (Boundary) : Initialise a 0 au lieu de kills[0] */
int titans_kadane_mutant_a(int *kills, int size)
{
    if (!kills || size <= 0) return 0;

    int max_ending_here = 0;  // BUG : devrait etre kills[0]
    int max_so_far = 0;       // BUG : devrait etre kills[0]

    for (int i = 0; i < size; i++)  // BUG : devrait commencer a 1
    {
        max_ending_here = (kills[i] > max_ending_here + kills[i]) ? kills[i] : max_ending_here + kills[i];
        max_so_far = (max_ending_here > max_so_far) ? max_ending_here : max_so_far;
    }

    return max_so_far;
}
// Pourquoi c'est faux : Retourne 0 pour [-1, -2, -3] au lieu de -1
// Ce qui etait pense : "0 est neutre pour les sommes"
```

**Mutant B (Safety) : LCS sans verification NULL**

```c
/* Mutant B (Safety) : Pas de verification des chaines vides/NULL */
int levi_squad_lcs_mutant_b(const char *plan_a, const char *plan_b)
{
    // PAS DE VERIFICATION NULL !
    int n = strlen(plan_a);  // CRASH si NULL
    int m = strlen(plan_b);  // CRASH si NULL

    int **dp = malloc((n + 1) * sizeof(int *));
    for (int i = 0; i <= n; i++)
        dp[i] = calloc(m + 1, sizeof(int));

    for (int i = 1; i <= n; i++)
    {
        for (int j = 1; j <= m; j++)
        {
            if (plan_a[i - 1] == plan_b[j - 1])
                dp[i][j] = dp[i - 1][j - 1] + 1;
            else
                dp[i][j] = (dp[i - 1][j] > dp[i][j - 1]) ? dp[i - 1][j] : dp[i][j - 1];
        }
    }

    int result = dp[n][m];
    for (int i = 0; i <= n; i++)
        free(dp[i]);
    free(dp);
    return result;
}
// Pourquoi c'est faux : Segfault sur NULL ou chaine vide
// Ce qui etait pense : "Les entrees sont toujours valides"
```

**Mutant C (Initialization) : Edit Distance sans cas de base**

```c
/* Mutant C (Initialization) : Pas d'initialisation des bords */
int eren_transform_mutant_c(const char *source, const char *target)
{
    if (!source) source = "";
    if (!target) target = "";

    int n = strlen(source);
    int m = strlen(target);

    int **dp = malloc((n + 1) * sizeof(int *));
    for (int i = 0; i <= n; i++)
        dp[i] = calloc(m + 1, sizeof(int));  // Tout a 0 !

    // MANQUE : dp[i][0] = i et dp[0][j] = j

    for (int i = 1; i <= n; i++)
    {
        for (int j = 1; j <= m; j++)
        {
            if (source[i - 1] == target[j - 1])
                dp[i][j] = dp[i - 1][j - 1];
            else
                dp[i][j] = 1 + min3(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
        }
    }

    int result = dp[n][m];
    for (int i = 0; i <= n; i++)
        free(dp[i]);
    free(dp);
    return result;
}
// Pourquoi c'est faux : eren_transform("", "ABC") retourne 0 au lieu de 3
// Ce qui etait pense : "calloc initialise tout correctement"
```

**Mutant D (Logic) : LCS sans +1 sur match**

```c
/* Mutant D (Logic) : Oublie d'incrementer sur match */
int levi_squad_lcs_mutant_d(const char *plan_a, const char *plan_b)
{
    if (!plan_a || !plan_b) return 0;

    int n = strlen(plan_a);
    int m = strlen(plan_b);
    if (n == 0 || m == 0) return 0;

    int **dp = malloc((n + 1) * sizeof(int *));
    for (int i = 0; i <= n; i++)
        dp[i] = calloc(m + 1, sizeof(int));

    for (int i = 1; i <= n; i++)
    {
        for (int j = 1; j <= m; j++)
        {
            if (plan_a[i - 1] == plan_b[j - 1])
                dp[i][j] = dp[i - 1][j - 1];  // BUG : manque + 1 !
            else
                dp[i][j] = (dp[i - 1][j] > dp[i][j - 1]) ? dp[i - 1][j] : dp[i][j - 1];
        }
    }

    int result = dp[n][m];
    for (int i = 0; i <= n; i++)
        free(dp[i]);
    free(dp);
    return result;
}
// Pourquoi c'est faux : Retourne toujours 0
// Ce qui etait pense : "La recursion s'occupe d'incrementer"
```

**Mutant E (Return) : LIS retourne dp[n-1] au lieu de max(dp)**

```c
/* Mutant E (Return) : Retourne le dernier element au lieu du max */
int lis_freedom_path_mutant_e(int *altitudes, int size)
{
    if (!altitudes || size <= 0) return 0;

    int *dp = malloc(size * sizeof(int));
    for (int i = 0; i < size; i++)
        dp[i] = 1;

    for (int i = 1; i < size; i++)
    {
        for (int j = 0; j < i; j++)
        {
            if (altitudes[j] < altitudes[i] && dp[j] + 1 > dp[i])
                dp[i] = dp[j] + 1;
        }
    }

    int result = dp[size - 1];  // BUG : devrait etre max(dp)
    free(dp);
    return result;
}
// Pourquoi c'est faux : LIS peut ne pas finir au dernier element
// Exemple : [1, 3, 2] -> dp = [1, 2, 2], retourne 2 (correct par chance)
// Mais [3, 1, 2] -> dp = [1, 1, 2], retourne 2 (correct)
// Mais [10, 9, 2, 5, 3, 7, 101, 18] -> dp[7] = 4, mais max pourrait etre ailleurs
// Ce qui etait pense : "La LIS finit forcement au dernier element"
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

Cet exercice de synthese couvre les 5 algorithmes fondamentaux de **programmation dynamique sur sequences** :

| Algorithme | Probleme | Complexite | Application |
|------------|----------|------------|-------------|
| **Kadane** | Max Subarray Sum | O(n) temps, O(1) espace | Trading, signal processing |
| **LCS** | Longest Common Subsequence | O(n*m) temps, O(n*m) espace | Diff, versionning, ADN |
| **Edit Distance** | Transformation minimale | O(n*m) temps, O(n*m) espace | Spell check, bioinformatique |
| **LIS** | Longest Increasing Subsequence | O(n^2) ou O(n log n) | Patience sorting, statistiques |
| **Palindrome LPS** | Longest Palindromic Subsequence | O(n^2) temps, O(n^2) espace | Compression, genetique |

**Concept cle :** La DP decompose un probleme en sous-problemes overlapping et utilise une table pour eviter les recalculs.

---

### 5.2 LDA — Traduction litterale en francais (MAJUSCULES)

#### 5.2.1 Kadane

```
FONCTION titans_kadane QUI RETOURNE UN ENTIER ET PREND EN PARAMETRE kills QUI EST UN POINTEUR VERS UN TABLEAU D'ENTIERS ET size QUI EST UN ENTIER
DEBUT FONCTION
    SI kills EST EGAL A NUL OU size EST INFERIEUR OU EGAL A 0 ALORS
        RETOURNER LA VALEUR 0
    FIN SI

    DECLARER max_ending_here COMME ENTIER
    DECLARER max_so_far COMME ENTIER

    AFFECTER LE PREMIER ELEMENT DE kills A max_ending_here
    AFFECTER LE PREMIER ELEMENT DE kills A max_so_far

    POUR i ALLANT DE 1 A size MOINS 1 FAIRE
        SI L'ELEMENT A LA POSITION i DANS kills EST SUPERIEUR A max_ending_here PLUS L'ELEMENT A LA POSITION i DANS kills ALORS
            AFFECTER L'ELEMENT A LA POSITION i DANS kills A max_ending_here
        SINON
            AFFECTER max_ending_here PLUS L'ELEMENT A LA POSITION i DANS kills A max_ending_here
        FIN SI

        SI max_ending_here EST SUPERIEUR A max_so_far ALORS
            AFFECTER max_ending_here A max_so_far
        FIN SI
    FIN POUR

    RETOURNER max_so_far
FIN FONCTION
```

#### 5.2.2 LCS (Style Academique)

```
ALGORITHME : Plus Longue Sous-Sequence Commune (LCS)

ENTREES :
    - plan_a : chaine de caracteres de longueur n
    - plan_b : chaine de caracteres de longueur m

SORTIE :
    - Longueur de la plus longue sous-sequence commune

VARIABLES :
    - dp : matrice (n+1) x (m+1) d'entiers
    - i, j : indices entiers

DEBUT
    INITIALISER dp[0][j] = 0 pour tout j de 0 a m
    INITIALISER dp[i][0] = 0 pour tout i de 0 a n

    POUR i DE 1 A n FAIRE
        POUR j DE 1 A m FAIRE
            SI plan_a[i-1] = plan_b[j-1] ALORS
                dp[i][j] <- dp[i-1][j-1] + 1
            SINON
                dp[i][j] <- MAX(dp[i-1][j], dp[i][j-1])
            FIN SI
        FIN POUR
    FIN POUR

    RETOURNER dp[n][m]
FIN
```

#### 5.2.2.1 Logic Flow (Structured English)

```
ALGORITHME : Longest Common Subsequence
---
1. VERIFIER si l'une des chaines est vide
   - Si OUI : RETOURNER 0

2. CREER une matrice dp de taille (n+1) x (m+1)

3. INITIALISER la premiere ligne et colonne a 0

4. POUR CHAQUE position (i, j) de 1 a (n, m) :
   a. SI les caracteres matchent :
      - dp[i][j] = dp[i-1][j-1] + 1 (diagonal + 1)
   b. SINON :
      - dp[i][j] = MAX(dp[i-1][j], dp[i][j-1]) (haut ou gauche)

5. RETOURNER dp[n][m] (coin bas-droit)
```

#### 5.2.3 Representation Algorithmique (Edit Distance)

```
FONCTION : eren_transform(source, target)
---
INIT dp[0..n][0..m]

1. CAS DE BASE :
   |
   |-- dp[i][0] = i pour tout i (supprimer tous les caracteres de source)
   |
   |-- dp[0][j] = j pour tout j (inserer tous les caracteres de target)

2. RECURRENCE :
   |
   |-- SI source[i-1] == target[j-1] :
   |     dp[i][j] = dp[i-1][j-1]  // Pas d'operation
   |
   |-- SINON :
   |     dp[i][j] = 1 + MIN(
   |         dp[i-1][j-1],  // Remplacer
   |         dp[i-1][j],    // Supprimer
   |         dp[i][j-1]     // Inserer
   |     )

3. RETOURNER dp[n][m]
```

#### 5.2.3.1 Logique de Garde (LIS)

```
FONCTION : lis_freedom_path(altitudes, size)
---
INIT result = 0

1. VERIFIER si le tableau est vide ou NULL :
   |
   |-- SI altitudes == NULL OU size <= 0 :
   |     RETOURNER 0

2. INITIALISER dp[i] = 1 pour tout i :
   |
   |-- Chaque element est une LIS de longueur 1 en lui-meme

3. POUR CHAQUE element i de 1 a size-1 :
   |
   |-- POUR CHAQUE element j de 0 a i-1 :
   |     |
   |     |-- SI altitudes[j] < altitudes[i] :
   |     |     dp[i] = MAX(dp[i], dp[j] + 1)

4. RETOURNER MAX(dp)
```

**Diagramme Mermaid (Kadane) :**

```mermaid
graph TD
    A[Debut: titans_kadane] --> B{Tableau vide ?}
    B -- Oui --> C[RETOUR: 0]
    B -- Non --> D[max_here = max_far = arr[0]]

    D --> E{i < size ?}
    E -- Non --> K[RETOUR: max_far]
    E -- Oui --> F{arr[i] > max_here + arr[i] ?}

    F -- Oui --> G[max_here = arr[i]]
    F -- Non --> H[max_here = max_here + arr[i]]

    G --> I{max_here > max_far ?}
    H --> I

    I -- Oui --> J[max_far = max_here]
    I -- Non --> L[i++]
    J --> L

    L --> E
```

---

### 5.3 Visualisation ASCII

#### Kadane : Sliding Window Mental Model

```
Array:    [-2]  [1]  [-3]  [4]  [-1]  [2]  [1]  [-5]  [4]
           |     |     |    |     |    |    |     |    |
max_here: -2    1    -2    4     3    5    6     1    5
           |     |     |    |     |    |    |     |    |
max_far:  -2    1     1    4     4    5    6     6    6
                           └──────────────────────┘
                              Meilleure sequence: [4, -1, 2, 1] = 6
```

#### LCS : Matrice DP

```
        ""   D    E    F    E    N    D
    ""   0    0    0    0    0    0    0
     A   0    0    0    0    0    0    0
     T   0    0    0    0    0    0    0
     T   0    0    0    0    0    0    0
     A   0    0    0    0    0    0    0
     C   0    0    0    0    0    0    0
     K   0    0    0    0    0    0    0

Recurrence:
┌─────────────────────────────────────────┐
│ Si match : ↖ + 1                        │
│ Sinon    : max(↑, ←)                    │
└─────────────────────────────────────────┘
```

#### Edit Distance : Operations

```
EREN → TITAN

E → T  (replace)  TREN
R → I  (replace)  TIEN
E → T  (replace)  TITN
N → A  (replace)  TITA
    N  (insert)   TITAN

Total : 5 operations
```

#### LIS : Construction Progressive

```
Array: [10, 9, 2, 5, 3, 7, 101, 18]

dp[i] = longueur de la LIS se terminant a i

i=0: [10]           dp[0] = 1
i=1: [9]            dp[1] = 1  (9 < 10, pas d'extension)
i=2: [2]            dp[2] = 1  (2 < tout)
i=3: [2, 5]         dp[3] = 2  (5 > 2)
i=4: [2, 3]         dp[4] = 2  (3 > 2)
i=5: [2, 3, 7]      dp[5] = 3  (7 > 3)
i=6: [2, 3, 7, 101] dp[6] = 4  (101 > 7)
i=7: [2, 3, 7, 18]  dp[7] = 4  (18 > 7)

LIS = [2, 3, 7, 18] ou [2, 5, 7, 101] etc.
Longueur = 4
```

#### Palindrome : Sous-Sequence

```
BBABCBAB

Visualisation de la sous-sequence palindromique:
B B A B C B A B
│ │   │   │   │
└─┼───┼───┼───┘
  │   │   │
  └───┼───┘
      │

LPS = "BABCBAB" (longueur 7)
```

---

### 5.4 Les pieges en detail

#### Piege 1 : Kadane et les nombres negatifs

**Le probleme :**
```c
int max_sum = 0;  // FAUX!
```

Si tous les nombres sont negatifs, `max_sum` restera 0, ce qui est incorrect.

**La solution :**
```c
int max_sum = kills[0];  // Initialiser au premier element
```

---

#### Piege 2 : LCS Sous-sequence vs Sous-chaine

**Confusion courante :**
- **Sous-chaine** : elements contigus ("ABC" dans "XABCY")
- **Sous-sequence** : elements dans l'ordre mais pas forcement contigus ("AC" dans "XABCY")

La LCS cherche une **sous-sequence**, pas une sous-chaine.

---

#### Piege 3 : Edit Distance et les cas de base

**Erreur :**
```c
for (int i = 0; i <= n; i++)
    dp[i] = calloc(m + 1, sizeof(int));  // Tout a 0
```

**Probleme :** `dp[i][0]` devrait etre `i` (cout de supprimer i caracteres), et `dp[0][j]` devrait etre `j` (cout d'inserer j caracteres).

---

#### Piege 4 : LIS Strictement Croissant

**Erreur :**
```c
if (altitudes[j] <= altitudes[i])  // <= au lieu de <
```

Avec `<=`, on autorise les egalites, ce qui donne la **Longest Non-Decreasing Subsequence**, pas la LIS.

---

#### Piege 5 : Palindrome et les indices

**Erreur courante :** Confondre `dp[i][j]` avec la longueur du palindrome **entre** i et j vs **jusqu'a** i et j.

**Convention :** `dp[i][j]` = longueur du plus long palindrome dans `s[i..j]` (inclus).

---

### 5.5 Cours Complet (VRAI cours, pas un resume)

#### 5.5.1 Introduction a la Programmation Dynamique

La **programmation dynamique** (DP) est une technique d'optimisation qui resout des problemes en les decomposant en **sous-problemes overlapping** (qui se chevauchent). Au lieu de recalculer les memes sous-problemes plusieurs fois (comme en recursion naive), on stocke les resultats dans une **table** (souvent appelee `dp`).

**Les 3 ingredients de la DP :**

1. **Sous-structure optimale** : La solution optimale du probleme peut etre construite a partir des solutions optimales de ses sous-problemes.

2. **Chevauchement des sous-problemes** : Les memes sous-problemes sont resolus plusieurs fois.

3. **Memoization ou Tabulation** :
   - **Memoization** (top-down) : Recursion + cache
   - **Tabulation** (bottom-up) : Remplir une table iterativement

---

#### 5.5.2 Algorithme de Kadane (1984)

**Probleme :** Trouver la somme maximale d'un sous-tableau contigu.

**Intuition :** A chaque position, on se demande : "Dois-je continuer la sequence precedente ou en commencer une nouvelle ?"

**Recurrence :**
```
max_ending_here[i] = max(arr[i], max_ending_here[i-1] + arr[i])
```

Si `arr[i]` seul est plus grand que la somme precedente + `arr[i]`, on "reset" et on recommence a `arr[i]`.

**Pourquoi ca marche ?**
- Si la somme courante devient negative, il vaut mieux repartir de zero (ou du prochain element).
- On garde toujours le maximum global (`max_so_far`).

**Complexite :** O(n) temps, O(1) espace — optimal!

---

#### 5.5.3 Longest Common Subsequence (LCS)

**Probleme :** Trouver la longueur de la plus longue sous-sequence presente dans les deux chaines.

**Recurrence :**
```
Si A[i-1] == B[j-1]:
    dp[i][j] = dp[i-1][j-1] + 1
Sinon:
    dp[i][j] = max(dp[i-1][j], dp[i][j-1])
```

**Intuition :**
- Si les caracteres matchent, on etend la LCS precedente de 1.
- Sinon, on prend le meilleur entre "ignorer le caractere de A" et "ignorer le caractere de B".

**Applications reelles :**
- `git diff` : Trouve les lignes communes entre deux versions
- Bioinformatique : Alignement de sequences ADN
- Plagiarism detection

---

#### 5.5.4 Edit Distance (Levenshtein, 1965)

**Probleme :** Nombre minimum d'operations (insert, delete, replace) pour transformer une chaine en une autre.

**Recurrence :**
```
Si source[i-1] == target[j-1]:
    dp[i][j] = dp[i-1][j-1]  // Pas d'operation
Sinon:
    dp[i][j] = 1 + min(
        dp[i-1][j-1],  // Replace
        dp[i-1][j],    // Delete from source
        dp[i][j-1]     // Insert into source
    )
```

**Cas de base :**
- `dp[i][0] = i` : Supprimer i caracteres de source
- `dp[0][j] = j` : Inserer j caracteres dans source

**Applications reelles :**
- Correcteurs orthographiques (suggestions de mots)
- Bioinformatique (mutations genetiques)
- Fuzzy matching (recherche approximative)

---

#### 5.5.5 Longest Increasing Subsequence (LIS)

**Probleme :** Trouver la longueur de la plus longue sous-sequence strictement croissante.

**Approche O(n^2) :**
```
dp[i] = longueur de la LIS se terminant a l'indice i

Pour chaque i:
    Pour chaque j < i:
        Si arr[j] < arr[i]:
            dp[i] = max(dp[i], dp[j] + 1)

Resultat = max(dp)
```

**Approche O(n log n) avec recherche binaire :**
On maintient un tableau `tails` ou `tails[k]` est le plus petit element final d'une LIS de longueur k+1.

```
Pour chaque element:
    - Trouver sa position avec binary search
    - Mettre a jour tails
```

**Lien avec les permutations :**
La LIS est liee au theoreme d'Erdos-Szekeres : toute sequence de n^2 + 1 nombres distincts contient une sous-sequence croissante OU decroissante de longueur n+1.

---

#### 5.5.6 Longest Palindromic Subsequence (LPS)

**Probleme :** Trouver la longueur de la plus longue sous-sequence qui est un palindrome.

**Recurrence :**
```
Si s[i] == s[j]:
    dp[i][j] = dp[i+1][j-1] + 2
Sinon:
    dp[i][j] = max(dp[i+1][j], dp[i][j-1])

Base: dp[i][i] = 1 (chaque caractere est un palindrome de longueur 1)
```

**Ordre de remplissage :** Par longueur croissante de sous-chaine (diagonale → coin).

**Astuce :** LPS(s) = LCS(s, reverse(s))

---

### 5.6 Normes avec explications pedagogiques

```
┌─────────────────────────────────────────────────────────────────┐
│ ❌ HORS NORME (compile, mais interdit)                          │
├─────────────────────────────────────────────────────────────────┤
│ int **dp = malloc((n+1) * sizeof(int *));                       │
│ for (int i = 0; i <= n; i++)                                    │
│     dp[i] = malloc((m+1) * sizeof(int));                        │
│ // ... utilisation ...                                          │
│ // PAS DE FREE!                                                 │
├─────────────────────────────────────────────────────────────────┤
│ ✅ CONFORME                                                     │
├─────────────────────────────────────────────────────────────────┤
│ int **dp = malloc((n+1) * sizeof(int *));                       │
│ for (int i = 0; i <= n; i++)                                    │
│     dp[i] = malloc((m+1) * sizeof(int));                        │
│ // ... utilisation ...                                          │
│ for (int i = 0; i <= n; i++)                                    │
│     free(dp[i]);                                                │
│ free(dp);                                                       │
├─────────────────────────────────────────────────────────────────┤
│ 📖 POURQUOI ?                                                   │
│                                                                 │
│ • Memory leaks : Chaque malloc doit avoir son free              │
│ • Valgrind : Outil de detection de fuites memoire               │
│ • Production : Les fuites s'accumulent et crashent le serveur   │
└─────────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────────┐
│ ❌ HORS NORME                                                   │
├─────────────────────────────────────────────────────────────────┤
│ max_sum = max_sum > current ? max_sum : current;                │
├─────────────────────────────────────────────────────────────────┤
│ ✅ CONFORME                                                     │
├─────────────────────────────────────────────────────────────────┤
│ if (current > max_sum)                                          │
│     max_sum = current;                                          │
├─────────────────────────────────────────────────────────────────┤
│ 📖 POURQUOI ?                                                   │
│                                                                 │
│ • Lisibilite : Le ternaire complexe est difficile a debugger    │
│ • Breakpoints : Impossible de mettre un breakpoint sur le ?:    │
│ • Clarté : L'intention est plus claire avec if/else             │
└─────────────────────────────────────────────────────────────────┘
```

---

### 5.7 Simulation avec trace d'execution

#### Kadane sur [-2, 1, -3, 4, -1, 2, 1, -5, 4]

```
┌───────┬──────────────────────────────────┬───────────────┬─────────────┬─────────────────────────┐
│ Etape │ Instruction                      │ max_ending    │ max_so_far  │ Explication             │
├───────┼──────────────────────────────────┼───────────────┼─────────────┼─────────────────────────┤
│   1   │ Init avec arr[0] = -2            │     -2        │     -2      │ Premier element         │
├───────┼──────────────────────────────────┼───────────────┼─────────────┼─────────────────────────┤
│   2   │ i=1: max(1, -2+1) = max(1,-1)    │      1        │      1      │ Reset a 1 (1 > -1)      │
├───────┼──────────────────────────────────┼───────────────┼─────────────┼─────────────────────────┤
│   3   │ i=2: max(-3, 1-3) = max(-3,-2)   │     -2        │      1      │ Continue (-2 > -3)      │
├───────┼──────────────────────────────────┼───────────────┼─────────────┼─────────────────────────┤
│   4   │ i=3: max(4, -2+4) = max(4, 2)    │      4        │      4      │ Reset a 4 (4 > 2)       │
├───────┼──────────────────────────────────┼───────────────┼─────────────┼─────────────────────────┤
│   5   │ i=4: max(-1, 4-1) = max(-1, 3)   │      3        │      4      │ Continue (3 > -1)       │
├───────┼──────────────────────────────────┼───────────────┼─────────────┼─────────────────────────┤
│   6   │ i=5: max(2, 3+2) = max(2, 5)     │      5        │      5      │ Continue (5 > 2)        │
├───────┼──────────────────────────────────┼───────────────┼─────────────┼─────────────────────────┤
│   7   │ i=6: max(1, 5+1) = max(1, 6)     │      6        │      6      │ Continue (6 > 1)        │
├───────┼──────────────────────────────────┼───────────────┼─────────────┼─────────────────────────┤
│   8   │ i=7: max(-5, 6-5) = max(-5, 1)   │      1        │      6      │ Continue (1 > -5)       │
├───────┼──────────────────────────────────┼───────────────┼─────────────┼─────────────────────────┤
│   9   │ i=8: max(4, 1+4) = max(4, 5)     │      5        │      6      │ Continue (5 > 4)        │
├───────┼──────────────────────────────────┼───────────────┼─────────────┼─────────────────────────┤
│  10   │ RETOURNER max_so_far             │      —        │      6      │ Resultat final : 6      │
└───────┴──────────────────────────────────┴───────────────┴─────────────┴─────────────────────────┘
```

---

### 5.8 Mnemotechniques (MEME obligatoire)

#### 🔥 MEME : "TATAKAE!" — Eren et la recurrence DP

![Eren TATAKAE](eren_tatakae.jpg)

*"TATAKAE! TATAKAE!"* crie Eren dans le miroir.

Comme Eren qui se bat (tatakae) a **chaque etape** contre lui-meme, la DP resout le probleme **etape par etape**, en se basant sur les decisions precedentes.

```rust
// Chaque etape, on se demande : "On continue ou on recommence ?"
max_here = std::cmp::max(arr[i], max_here + arr[i]);  // TATAKAE!
```

---

#### 🏰 MEME : "Les 3 Murs" — Edit Distance

Les 3 murs de Paradis (Maria, Rose, Sina) representent les 3 operations d'Edit Distance :

```
       WALL MARIA (Delete) ←─┐
              │              │
       WALL ROSE (Replace) ←─┼── 3 choix a chaque etape
              │              │
       WALL SINA (Insert) ←──┘

dp[i][j] = 1 + min(Maria, Rose, Sina)
```

---

#### 💀 MEME : "Levi's Choice" — Kadane Reset

Levi doit parfois **abandonner** ses soldats pour sauver la mission.

Kadane fait pareil : parfois il vaut mieux **reset** (abandonner la somme courante) que de trainer un passe negatif.

```c
if (current_sum < 0)
    current_sum = arr[i];  // Levi abandonne le passe pour la mission
```

---

#### 🌊 MEME : "Reaching the Sea" — LIS

Le reve d'Eren est d'atteindre la mer. Mais le chemin doit etre **toujours ascendant** (vers la liberte).

LIS = trouver le plus long chemin ou chaque etape est **plus haute** que la precedente.

```
[10, 9, 2, 5, 3, 7, 101, 18]
         └──┴──┴──┴──────────┘
         Chemin ascendant vers la mer
```

---

#### 👑 MEME : "Royal Blood Palindrome" — Memoires des Reiss

Les memoires de la famille royale se lisent **dans les deux sens** — comme un palindrome.

Le secret est que `LPS(s) = LCS(s, reverse(s))`.

```
HISTORIA → LPS = LCS("HISTORIA", "AIROTSIS")
```

---

### 5.9 Applications pratiques

| Algorithme | Application Reelle | Exemple Concret |
|------------|-------------------|-----------------|
| **Kadane** | Trading algorithmique | Trouver la meilleure periode pour acheter/vendre une action |
| **LCS** | Git diff | Afficher les lignes ajoutees/supprimees entre deux commits |
| **Edit Distance** | Google Search | "Did you mean: attack on titan" quand tu tapes "atack on titen" |
| **LIS** | Scheduling | Trouver le maximum de taches qui peuvent etre faites sans conflit |
| **LPS** | Compression ADN | Detecter les sequences palindromiques dans l'ADN |

---

## SECTION 6 : PIEGES — RECAPITULATIF

| Piege | Description | Comment eviter |
|-------|-------------|----------------|
| **Kadane Init** | Initialiser a 0 au lieu de arr[0] | `max_sum = arr[0]` |
| **Kadane All Neg** | Retourner 0 pour tous negatifs | Garder le moins negatif |
| **LCS vs Substring** | Confondre sous-sequence et sous-chaine | Les elements n'ont pas besoin d'etre contigus |
| **Edit Base Case** | Oublier dp[i][0]=i, dp[0][j]=j | Initialiser les bords correctement |
| **LIS Equality** | `<=` au lieu de `<` | Strictement croissant = `<` uniquement |
| **LIS Max** | Retourner dp[n-1] au lieu de max(dp) | La LIS peut ne pas finir au dernier element |
| **Memory Leak** | Pas de free() | Chaque malloc a son free |
| **NULL Check** | Pas de verification NULL | Toujours verifier les entrees |

---

## SECTION 7 : QCM

### Question 1
Quelle est la complexite temporelle de l'algorithme de Kadane ?

- A) O(1)
- B) O(log n)
- C) O(n)
- D) O(n log n)
- E) O(n^2)
- F) O(n^3)
- G) O(2^n)
- H) O(n!)
- I) Depend de l'implementation
- J) Aucune de ces reponses

**Reponse : C**

---

### Question 2
Pour l'Edit Distance, que represente `dp[i][0]` ?

- A) 0
- B) i
- C) Le nombre de caracteres identiques
- D) La longueur de source
- E) La longueur de target
- F) Le minimum entre i et 0
- G) Le maximum entre i et 0
- H) i * 0
- I) Indefini
- J) Depend du cas

**Reponse : B** (cout de supprimer i caracteres de source)

---

### Question 3
Quelle est la recurrence de LCS quand les caracteres NE matchent PAS ?

- A) dp[i][j] = 0
- B) dp[i][j] = dp[i-1][j-1]
- C) dp[i][j] = dp[i-1][j-1] + 1
- D) dp[i][j] = max(dp[i-1][j], dp[i][j-1])
- E) dp[i][j] = min(dp[i-1][j], dp[i][j-1])
- F) dp[i][j] = dp[i-1][j] + dp[i][j-1]
- G) dp[i][j] = dp[i][j-1] - dp[i-1][j]
- H) dp[i][j] = 1
- I) dp[i][j] = max(dp[i-1][j], dp[i][j-1]) + 1
- J) Aucune de ces reponses

**Reponse : D**

---

### Question 4
`titans_kadane([-5, -3, -1, -4])` retourne :

- A) 0
- B) -1
- C) -3
- D) -5
- E) -13
- F) -4
- G) 1
- H) Erreur
- I) NULL
- J) Undefined behavior

**Reponse : B** (le moins negatif = -1)

---

### Question 5
Quelle optimisation permet de passer LIS de O(n^2) a O(n log n) ?

- A) Memoization
- B) Tri prealable
- C) Recherche binaire
- D) Hash table
- E) Recursion tail
- F) Parallelisation
- G) Cache locality
- H) Bit manipulation
- I) Space-time tradeoff
- J) Aucune optimisation possible

**Reponse : C**

---

### Question 6
`levi_squad_lcs("ABCD", "")` retourne :

- A) 0
- B) 4
- C) -1
- D) NULL
- E) Erreur
- F) 1
- G) Undefined
- H) ""
- I) Crash
- J) Depend de l'implementation

**Reponse : A** (chaine vide = LCS 0)

---

### Question 7
Quelle relation lie LPS et LCS ?

- A) LPS = LCS + 1
- B) LPS = LCS * 2
- C) LPS(s) = LCS(s, reverse(s))
- D) LPS = LCS / 2
- E) Aucune relation
- F) LPS = LCS pour les palindromes
- G) LPS > LCS toujours
- H) LPS < LCS toujours
- I) LPS = len(s) - LCS
- J) Aucune de ces reponses

**Reponse : C**

---

### Question 8
Dans Edit Distance, "replace" correspond a quelle case de la matrice DP ?

- A) dp[i-1][j]
- B) dp[i][j-1]
- C) dp[i-1][j-1]
- D) dp[i+1][j+1]
- E) dp[i][j]
- F) dp[0][0]
- G) dp[n][m]
- H) dp[i-1][j] + dp[i][j-1]
- I) Aucune de ces cases
- J) Depend de l'operation

**Reponse : C** (diagonal = replace)

---

### Question 9
`lis_freedom_path([5, 5, 5, 5])` retourne :

- A) 0
- B) 1
- C) 4
- D) 5
- E) Erreur
- F) -1
- G) Undefined
- H) 2
- I) 3
- J) Depend de l'implementation

**Reponse : B** (strictement croissant, pas d'egalite)

---

### Question 10
Quelle est la complexite spatiale de LCS classique ?

- A) O(1)
- B) O(n)
- C) O(m)
- D) O(n + m)
- E) O(n * m)
- F) O(min(n, m))
- G) O(max(n, m))
- H) O(n^2)
- I) O(log n)
- J) Depend de l'implementation

**Reponse : E** (matrice n × m)

---

## SECTION 8 : RECAPITULATIF

| Aspect | Valeur |
|--------|--------|
| **Module** | 1.5.2 — Sequence Dynamic Programming |
| **Exercice** | 1.5.2-synth : Survey Corps DP Arsenal |
| **Theme** | Attack on Titan |
| **Fonctions** | titans_kadane, levi_squad_lcs, eren_transform, lis_freedom_path, historia_palindrome |
| **Difficulte** | 6/10 (★★★★★★☆☆☆☆) |
| **Langages** | Rust Edition 2024 + C (C17) |
| **Duree** | 120 min |
| **XP Base** | 150 |
| **Bonus** | 🔥 Avance (×3 XP) |
| **Complexite Base** | O(n) a O(n*m) temps |
| **Complexite Bonus** | O(n log n) pour LIS |

---

## SECTION 9 : DEPLOYMENT PACK (JSON COMPLET)

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "1.5.2-synth-survey-corps-dp-arsenal",
    "generated_at": "2026-01-12 00:00:00",

    "metadata": {
      "exercise_id": "1.5.2-synth",
      "exercise_name": "survey_corps_dp_arsenal",
      "module": "1.5.2",
      "module_name": "Sequence Dynamic Programming",
      "concept": "synth",
      "concept_name": "Kadane + LCS + Edit Distance + LIS + Palindrome",
      "type": "complet",
      "tier": 3,
      "tier_info": "Synthese (concepts a→e)",
      "phase": 1,
      "difficulty": 6,
      "difficulty_stars": "★★★★★★☆☆☆☆",
      "languages": ["rust", "c"],
      "rust_edition": "2024",
      "c_version": "c17",
      "duration_minutes": 120,
      "xp_base": 150,
      "xp_bonus_multiplier": 3,
      "bonus_tier": "AVANCE",
      "bonus_icon": "🔥",
      "complexity_time": "T3 O(n) to O(n*m)",
      "complexity_space": "S3 O(1) to O(n*m)",
      "prerequisites": ["1.5.1-a", "1.5.1-b", "0.3.x", "0.4.x"],
      "domains": ["DP", "Algo", "Struct"],
      "domains_bonus": ["Algo", "Optim"],
      "tags": ["dp", "kadane", "lcs", "edit_distance", "lis", "palindrome", "aot", "attack_on_titan"],
      "theme": "Attack on Titan",
      "meme_reference": "TATAKAE"
    },

    "files": {
      "spec.json": "/* Section 4.9 */",
      "references/ref_titans_kadane.rs": "/* Section 4.3 */",
      "references/ref_titans_kadane.c": "/* Section 4.3 */",
      "references/ref_levi_squad_lcs.rs": "/* Section 4.3 */",
      "references/ref_levi_squad_lcs.c": "/* Section 4.3 */",
      "references/ref_eren_transform.rs": "/* Section 4.3 */",
      "references/ref_eren_transform.c": "/* Section 4.3 */",
      "references/ref_lis_freedom_path.rs": "/* Section 4.3 */",
      "references/ref_lis_freedom_path.c": "/* Section 4.3 */",
      "references/ref_historia_palindrome.rs": "/* Section 4.3 */",
      "references/ref_historia_palindrome.c": "/* Section 4.3 */",
      "references/ref_bonus_lcs_optimized.rs": "/* Section 4.6 */",
      "references/ref_bonus_lis_fast.rs": "/* Section 4.6 */",
      "alternatives/alt_kadane_v2.c": "/* Section 4.4 */",
      "alternatives/alt_lis_binary.c": "/* Section 4.4 */",
      "mutants/mutant_a_boundary.c": "/* Section 4.10 */",
      "mutants/mutant_b_safety.c": "/* Section 4.10 */",
      "mutants/mutant_c_init.c": "/* Section 4.10 */",
      "mutants/mutant_d_logic.c": "/* Section 4.10 */",
      "mutants/mutant_e_return.c": "/* Section 4.10 */",
      "tests/main.c": "/* Section 4.2 */",
      "tests/main.rs": "/* Section 4.2 adapted for Rust */"
    },

    "validation": {
      "expected_pass": [
        "references/ref_titans_kadane.rs",
        "references/ref_titans_kadane.c",
        "references/ref_levi_squad_lcs.rs",
        "references/ref_levi_squad_lcs.c",
        "references/ref_eren_transform.rs",
        "references/ref_eren_transform.c",
        "references/ref_lis_freedom_path.rs",
        "references/ref_lis_freedom_path.c",
        "references/ref_historia_palindrome.rs",
        "references/ref_historia_palindrome.c",
        "references/ref_bonus_lcs_optimized.rs",
        "references/ref_bonus_lis_fast.rs",
        "alternatives/alt_kadane_v2.c",
        "alternatives/alt_lis_binary.c"
      ],
      "expected_fail": [
        "mutants/mutant_a_boundary.c",
        "mutants/mutant_b_safety.c",
        "mutants/mutant_c_init.c",
        "mutants/mutant_d_logic.c",
        "mutants/mutant_e_return.c"
      ]
    },

    "commands": {
      "validate_spec": "python3 hackbrain_engine_v22.py --validate-spec spec.json",
      "test_reference_rust": "cargo test --edition 2024",
      "test_reference_c": "gcc -std=c17 -Wall -Wextra -Werror *.c -o test && ./test",
      "test_mutants": "python3 hackbrain_mutation_tester.py -s spec.json --validate"
    }
  }
}
```

---

*HACKBRAIN v5.5.2 — Prompt Systeme Unifie de Production d'Exercices*
*"L'excellence pedagogique ne se negocie pas — pas de raccourcis"*
*Compatible ENGINE v22.1 + Mutation Tester*

*Theme : Attack on Titan — "SHINZOU WO SASAGEYO!"*
