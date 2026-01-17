# Exercice D.0.28-a : string_algorithms

**Module :**
D.0.28 — Algorithmes de Chaines

**Concept :**
a-e — Pattern matching naive, KMP, Rabin-Karp, LCS, Levenshtein

**Difficulte :**
7/10

**Type :**
code

**Tiers :**
2 — Melange concepts

**Langage :**
C17

**Prerequis :**
D.0.13 (dynamic_programming), 0.5 (pointeurs), 0.4 (strings)

**Domaines :**
Algo, Strings

**Duree estimee :**
300 min

**XP Base :**
225

**Complexite :**
T[N] O(n+m) x S[N] O(m)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `string_algorithms.c`
- `string_algorithms.h`

### 1.2 Consigne

Implementer les algorithmes fondamentaux de traitement de chaines.

**Ta mission :**

```c
// Recherche de motif naive - retourne index de premiere occurrence (-1 si absent)
int naive_search(const char *text, const char *pattern);

// Retourne tous les indices d'occurrence (termine par -1)
int *naive_search_all(const char *text, const char *pattern, int *count);

// Knuth-Morris-Pratt - construction de la table de prefixes
int *kmp_build_lps(const char *pattern, int m);

// KMP search - retourne index de premiere occurrence (-1 si absent)
int kmp_search(const char *text, const char *pattern);

// KMP - retourne tous les indices d'occurrence
int *kmp_search_all(const char *text, const char *pattern, int *count);

// Rabin-Karp avec rolling hash
int rabin_karp_search(const char *text, const char *pattern);

// Rabin-Karp - retourne tous les indices d'occurrence
int *rabin_karp_search_all(const char *text, const char *pattern, int *count);

// Longest Common Subsequence - longueur
int lcs_length(const char *s1, const char *s2);

// LCS - retourne la sous-sequence
char *lcs_string(const char *s1, const char *s2);

// Edit Distance (Levenshtein)
int edit_distance(const char *s1, const char *s2);

// Edit Distance avec operations (retourne le chemin d'edition)
typedef struct {
    char operation;  // 'M' match, 'R' replace, 'I' insert, 'D' delete
    char c1;
    char c2;
} EditOp;
EditOp *edit_operations(const char *s1, const char *s2, int *op_count);
```

**Comportement:**

1. `naive_search("AABAACAADAABAAABAA", "AABA")` -> 0
2. `kmp_search("ABABDABACDABABCABAB", "ABABCABAB")` -> 10
3. `rabin_karp_search("GEEKS FOR GEEKS", "GEEK")` -> 0
4. `lcs_length("ABCDGH", "AEDFHR")` -> 3 (ADH)
5. `edit_distance("kitten", "sitting")` -> 3

**Exemples:**
```
Recherche naive de "AABA" dans "AABAACAADAABAAABAA":

Position 0: AABA = AABA  -> MATCH!
Position 1: ABAA != AABA
Position 2: BAAC != AABA
...

KMP avec LPS table pour "ABABCABAB":
Pattern: A B A B C A B A B
LPS:     0 0 1 2 0 1 2 3 4

Rabin-Karp (base 256, mod 101):
hash("GEEK") = (71*256^3 + 69*256^2 + 69*256 + 75) mod 101

LCS de "ABCBDAB" et "BDCAB":
     ""  B  D  C  A  B
""    0  0  0  0  0  0
A     0  0  0  0  1  1
B     0  1  1  1  1  2
C     0  1  1  2  2  2
B     0  1  1  2  2  3
D     0  1  2  2  2  3
A     0  1  2  2  3  3
B     0  1  2  2  3  4
-> LCS = "BDAB" ou "BCAB" (longueur 4)

Edit distance "kitten" -> "sitting":
kitten -> sitten (replace k->s)
sitten -> sittin (replace e->i)
sittin -> sitting (insert g)
Distance = 3
```

### 1.3 Prototype

```c
// string_algorithms.h
#ifndef STRING_ALGORITHMS_H
#define STRING_ALGORITHMS_H

// Recherche naive
int naive_search(const char *text, const char *pattern);
int *naive_search_all(const char *text, const char *pattern, int *count);

// Knuth-Morris-Pratt
int *kmp_build_lps(const char *pattern, int m);
int kmp_search(const char *text, const char *pattern);
int *kmp_search_all(const char *text, const char *pattern, int *count);

// Rabin-Karp
int rabin_karp_search(const char *text, const char *pattern);
int *rabin_karp_search_all(const char *text, const char *pattern, int *count);

// Longest Common Subsequence
int lcs_length(const char *s1, const char *s2);
char *lcs_string(const char *s1, const char *s2);

// Edit Distance (Levenshtein)
int edit_distance(const char *s1, const char *s2);

typedef struct {
    char operation;
    char c1;
    char c2;
} EditOp;
EditOp *edit_operations(const char *s1, const char *s2, int *op_count);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | naive_search basic | correct index | 10 |
| T02 | naive_search_all multiple | all indices | 10 |
| T03 | kmp_build_lps | correct LPS table | 15 |
| T04 | kmp_search | correct index | 15 |
| T05 | rabin_karp_search | correct index | 15 |
| T06 | lcs_length | correct length | 10 |
| T07 | lcs_string | valid LCS | 10 |
| T08 | edit_distance | correct distance | 15 |

### 4.3 Solution de reference

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "string_algorithms.h"

// ============================================================
// RECHERCHE NAIVE O(n*m)
// ============================================================

int naive_search(const char *text, const char *pattern)
{
    if (!text || !pattern)
        return -1;

    int n = strlen(text);
    int m = strlen(pattern);

    if (m == 0)
        return 0;
    if (m > n)
        return -1;

    for (int i = 0; i <= n - m; i++)
    {
        int j;
        for (j = 0; j < m; j++)
        {
            if (text[i + j] != pattern[j])
                break;
        }
        if (j == m)
            return i;
    }
    return -1;
}

int *naive_search_all(const char *text, const char *pattern, int *count)
{
    *count = 0;
    if (!text || !pattern)
        return NULL;

    int n = strlen(text);
    int m = strlen(pattern);

    if (m == 0 || m > n)
        return NULL;

    // Compter d'abord
    int capacity = 16;
    int *results = malloc(capacity * sizeof(int));

    for (int i = 0; i <= n - m; i++)
    {
        int j;
        for (j = 0; j < m; j++)
        {
            if (text[i + j] != pattern[j])
                break;
        }
        if (j == m)
        {
            if (*count >= capacity)
            {
                capacity *= 2;
                results = realloc(results, capacity * sizeof(int));
            }
            results[(*count)++] = i;
        }
    }

    return results;
}

// ============================================================
// KNUTH-MORRIS-PRATT O(n+m)
// ============================================================

int *kmp_build_lps(const char *pattern, int m)
{
    int *lps = calloc(m, sizeof(int));
    int len = 0;
    int i = 1;

    lps[0] = 0;

    while (i < m)
    {
        if (pattern[i] == pattern[len])
        {
            len++;
            lps[i] = len;
            i++;
        }
        else
        {
            if (len != 0)
            {
                len = lps[len - 1];
            }
            else
            {
                lps[i] = 0;
                i++;
            }
        }
    }

    return lps;
}

int kmp_search(const char *text, const char *pattern)
{
    if (!text || !pattern)
        return -1;

    int n = strlen(text);
    int m = strlen(pattern);

    if (m == 0)
        return 0;
    if (m > n)
        return -1;

    int *lps = kmp_build_lps(pattern, m);

    int i = 0;  // index pour text
    int j = 0;  // index pour pattern

    while (i < n)
    {
        if (pattern[j] == text[i])
        {
            i++;
            j++;
        }

        if (j == m)
        {
            free(lps);
            return i - j;
        }
        else if (i < n && pattern[j] != text[i])
        {
            if (j != 0)
                j = lps[j - 1];
            else
                i++;
        }
    }

    free(lps);
    return -1;
}

int *kmp_search_all(const char *text, const char *pattern, int *count)
{
    *count = 0;
    if (!text || !pattern)
        return NULL;

    int n = strlen(text);
    int m = strlen(pattern);

    if (m == 0 || m > n)
        return NULL;

    int *lps = kmp_build_lps(pattern, m);

    int capacity = 16;
    int *results = malloc(capacity * sizeof(int));

    int i = 0;
    int j = 0;

    while (i < n)
    {
        if (pattern[j] == text[i])
        {
            i++;
            j++;
        }

        if (j == m)
        {
            if (*count >= capacity)
            {
                capacity *= 2;
                results = realloc(results, capacity * sizeof(int));
            }
            results[(*count)++] = i - j;
            j = lps[j - 1];
        }
        else if (i < n && pattern[j] != text[i])
        {
            if (j != 0)
                j = lps[j - 1];
            else
                i++;
        }
    }

    free(lps);
    return results;
}

// ============================================================
// RABIN-KARP O(n+m) moyenne, O(n*m) pire cas
// ============================================================

#define RK_BASE 256
#define RK_MOD 101

int rabin_karp_search(const char *text, const char *pattern)
{
    if (!text || !pattern)
        return -1;

    int n = strlen(text);
    int m = strlen(pattern);

    if (m == 0)
        return 0;
    if (m > n)
        return -1;

    // Calculer h = BASE^(m-1) % MOD
    long h = 1;
    for (int i = 0; i < m - 1; i++)
        h = (h * RK_BASE) % RK_MOD;

    // Calculer hash initial du pattern et de la premiere fenetre
    long p_hash = 0;  // hash du pattern
    long t_hash = 0;  // hash de la fenetre courante

    for (int i = 0; i < m; i++)
    {
        p_hash = (RK_BASE * p_hash + pattern[i]) % RK_MOD;
        t_hash = (RK_BASE * t_hash + text[i]) % RK_MOD;
    }

    // Glisser la fenetre
    for (int i = 0; i <= n - m; i++)
    {
        // Si les hash correspondent, verifier caractere par caractere
        if (p_hash == t_hash)
        {
            int j;
            for (j = 0; j < m; j++)
            {
                if (text[i + j] != pattern[j])
                    break;
            }
            if (j == m)
                return i;
        }

        // Calculer le hash de la prochaine fenetre
        if (i < n - m)
        {
            t_hash = (RK_BASE * (t_hash - text[i] * h) + text[i + m]) % RK_MOD;
            if (t_hash < 0)
                t_hash += RK_MOD;
        }
    }

    return -1;
}

int *rabin_karp_search_all(const char *text, const char *pattern, int *count)
{
    *count = 0;
    if (!text || !pattern)
        return NULL;

    int n = strlen(text);
    int m = strlen(pattern);

    if (m == 0 || m > n)
        return NULL;

    int capacity = 16;
    int *results = malloc(capacity * sizeof(int));

    long h = 1;
    for (int i = 0; i < m - 1; i++)
        h = (h * RK_BASE) % RK_MOD;

    long p_hash = 0;
    long t_hash = 0;

    for (int i = 0; i < m; i++)
    {
        p_hash = (RK_BASE * p_hash + pattern[i]) % RK_MOD;
        t_hash = (RK_BASE * t_hash + text[i]) % RK_MOD;
    }

    for (int i = 0; i <= n - m; i++)
    {
        if (p_hash == t_hash)
        {
            int j;
            for (j = 0; j < m; j++)
            {
                if (text[i + j] != pattern[j])
                    break;
            }
            if (j == m)
            {
                if (*count >= capacity)
                {
                    capacity *= 2;
                    results = realloc(results, capacity * sizeof(int));
                }
                results[(*count)++] = i;
            }
        }

        if (i < n - m)
        {
            t_hash = (RK_BASE * (t_hash - text[i] * h) + text[i + m]) % RK_MOD;
            if (t_hash < 0)
                t_hash += RK_MOD;
        }
    }

    return results;
}

// ============================================================
// LONGEST COMMON SUBSEQUENCE O(n*m)
// ============================================================

int lcs_length(const char *s1, const char *s2)
{
    if (!s1 || !s2)
        return 0;

    int m = strlen(s1);
    int n = strlen(s2);

    // Allocation de la table DP
    int **dp = malloc((m + 1) * sizeof(int *));
    for (int i = 0; i <= m; i++)
        dp[i] = calloc(n + 1, sizeof(int));

    // Remplissage de la table
    for (int i = 1; i <= m; i++)
    {
        for (int j = 1; j <= n; j++)
        {
            if (s1[i - 1] == s2[j - 1])
                dp[i][j] = dp[i - 1][j - 1] + 1;
            else
                dp[i][j] = (dp[i - 1][j] > dp[i][j - 1]) ? dp[i - 1][j] : dp[i][j - 1];
        }
    }

    int result = dp[m][n];

    // Liberation memoire
    for (int i = 0; i <= m; i++)
        free(dp[i]);
    free(dp);

    return result;
}

char *lcs_string(const char *s1, const char *s2)
{
    if (!s1 || !s2)
        return NULL;

    int m = strlen(s1);
    int n = strlen(s2);

    // Allocation de la table DP
    int **dp = malloc((m + 1) * sizeof(int *));
    for (int i = 0; i <= m; i++)
        dp[i] = calloc(n + 1, sizeof(int));

    // Remplissage de la table
    for (int i = 1; i <= m; i++)
    {
        for (int j = 1; j <= n; j++)
        {
            if (s1[i - 1] == s2[j - 1])
                dp[i][j] = dp[i - 1][j - 1] + 1;
            else
                dp[i][j] = (dp[i - 1][j] > dp[i][j - 1]) ? dp[i - 1][j] : dp[i][j - 1];
        }
    }

    // Reconstruction de la LCS par backtracking
    int len = dp[m][n];
    char *lcs = malloc(len + 1);
    lcs[len] = '\0';

    int i = m, j = n;
    while (i > 0 && j > 0)
    {
        if (s1[i - 1] == s2[j - 1])
        {
            lcs[--len] = s1[i - 1];
            i--;
            j--;
        }
        else if (dp[i - 1][j] > dp[i][j - 1])
        {
            i--;
        }
        else
        {
            j--;
        }
    }

    // Liberation memoire
    for (int k = 0; k <= m; k++)
        free(dp[k]);
    free(dp);

    return lcs;
}

// ============================================================
// EDIT DISTANCE (LEVENSHTEIN) O(n*m)
// ============================================================

static int min3(int a, int b, int c)
{
    int min = a;
    if (b < min) min = b;
    if (c < min) min = c;
    return min;
}

int edit_distance(const char *s1, const char *s2)
{
    if (!s1 || !s2)
        return -1;

    int m = strlen(s1);
    int n = strlen(s2);

    // Allocation de la table DP
    int **dp = malloc((m + 1) * sizeof(int *));
    for (int i = 0; i <= m; i++)
        dp[i] = malloc((n + 1) * sizeof(int));

    // Cas de base: transformer chaine vide
    for (int i = 0; i <= m; i++)
        dp[i][0] = i;  // i deletions
    for (int j = 0; j <= n; j++)
        dp[0][j] = j;  // j insertions

    // Remplissage de la table
    for (int i = 1; i <= m; i++)
    {
        for (int j = 1; j <= n; j++)
        {
            if (s1[i - 1] == s2[j - 1])
            {
                dp[i][j] = dp[i - 1][j - 1];  // match, pas de cout
            }
            else
            {
                int insert_op = dp[i][j - 1] + 1;
                int delete_op = dp[i - 1][j] + 1;
                int replace_op = dp[i - 1][j - 1] + 1;
                dp[i][j] = min3(insert_op, delete_op, replace_op);
            }
        }
    }

    int result = dp[m][n];

    // Liberation memoire
    for (int i = 0; i <= m; i++)
        free(dp[i]);
    free(dp);

    return result;
}

EditOp *edit_operations(const char *s1, const char *s2, int *op_count)
{
    if (!s1 || !s2 || !op_count)
        return NULL;

    int m = strlen(s1);
    int n = strlen(s2);

    // Allocation de la table DP
    int **dp = malloc((m + 1) * sizeof(int *));
    for (int i = 0; i <= m; i++)
        dp[i] = malloc((n + 1) * sizeof(int));

    for (int i = 0; i <= m; i++)
        dp[i][0] = i;
    for (int j = 0; j <= n; j++)
        dp[0][j] = j;

    for (int i = 1; i <= m; i++)
    {
        for (int j = 1; j <= n; j++)
        {
            if (s1[i - 1] == s2[j - 1])
                dp[i][j] = dp[i - 1][j - 1];
            else
                dp[i][j] = 1 + min3(dp[i][j - 1], dp[i - 1][j], dp[i - 1][j - 1]);
        }
    }

    // Backtracking pour trouver les operations
    int max_ops = m + n;
    EditOp *ops = malloc(max_ops * sizeof(EditOp));
    *op_count = 0;

    int i = m, j = n;
    while (i > 0 || j > 0)
    {
        if (i > 0 && j > 0 && s1[i - 1] == s2[j - 1])
        {
            ops[(*op_count)].operation = 'M';
            ops[(*op_count)].c1 = s1[i - 1];
            ops[(*op_count)].c2 = s2[j - 1];
            (*op_count)++;
            i--;
            j--;
        }
        else if (j > 0 && (i == 0 || dp[i][j - 1] <= dp[i - 1][j] && dp[i][j - 1] <= dp[i - 1][j - 1]))
        {
            ops[(*op_count)].operation = 'I';
            ops[(*op_count)].c1 = '\0';
            ops[(*op_count)].c2 = s2[j - 1];
            (*op_count)++;
            j--;
        }
        else if (i > 0 && (j == 0 || dp[i - 1][j] <= dp[i][j - 1] && dp[i - 1][j] <= dp[i - 1][j - 1]))
        {
            ops[(*op_count)].operation = 'D';
            ops[(*op_count)].c1 = s1[i - 1];
            ops[(*op_count)].c2 = '\0';
            (*op_count)++;
            i--;
        }
        else
        {
            ops[(*op_count)].operation = 'R';
            ops[(*op_count)].c1 = s1[i - 1];
            ops[(*op_count)].c2 = s2[j - 1];
            (*op_count)++;
            i--;
            j--;
        }
    }

    // Liberation memoire
    for (int k = 0; k <= m; k++)
        free(dp[k]);
    free(dp);

    // Inverser l'ordre des operations (on a parcouru a l'envers)
    for (int k = 0; k < *op_count / 2; k++)
    {
        EditOp temp = ops[k];
        ops[k] = ops[*op_count - 1 - k];
        ops[*op_count - 1 - k] = temp;
    }

    return ops;
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: KMP LPS mal calcule - reset incorrect
int *kmp_build_lps(const char *pattern, int m)
{
    int *lps = calloc(m, sizeof(int));
    int len = 0;
    int i = 1;

    while (i < m)
    {
        if (pattern[i] == pattern[len])
        {
            len++;
            lps[i] = len;
            i++;
        }
        else
        {
            len = 0;  // ERREUR: devrait etre lps[len-1] si len != 0
            lps[i] = 0;
            i++;
        }
    }
    return lps;
}

// MUTANT 2: Rabin-Karp sans verification apres hash match
int rabin_karp_search(const char *text, const char *pattern)
{
    // ... hash calculation ...
    for (int i = 0; i <= n - m; i++)
    {
        if (p_hash == t_hash)
            return i;  // ERREUR: pas de verification caractere par caractere
                       // Faux positifs possibles (hash collision)
        // ... rolling hash ...
    }
    return -1;
}

// MUTANT 3: LCS mauvaise condition de comparaison
int lcs_length(const char *s1, const char *s2)
{
    // ...
    for (int i = 1; i <= m; i++)
    {
        for (int j = 1; j <= n; j++)
        {
            if (s1[i] == s2[j])  // ERREUR: indices i et j au lieu de i-1 et j-1
                dp[i][j] = dp[i - 1][j - 1] + 1;
            // ...
        }
    }
    // Acces hors limites et resultat incorrect
}

// MUTANT 4: Edit distance - oubli du cas match
int edit_distance(const char *s1, const char *s2)
{
    // ...
    for (int i = 1; i <= m; i++)
    {
        for (int j = 1; j <= n; j++)
        {
            // ERREUR: toujours prendre le min des 3 operations
            // meme quand les caracteres correspondent
            int insert_op = dp[i][j - 1] + 1;
            int delete_op = dp[i - 1][j] + 1;
            int replace_op = dp[i - 1][j - 1] + 1;
            dp[i][j] = min3(insert_op, delete_op, replace_op);
        }
    }
    // Distance toujours trop grande
}

// MUTANT 5: Naive search - condition de boucle incorrecte
int naive_search(const char *text, const char *pattern)
{
    int n = strlen(text);
    int m = strlen(pattern);

    for (int i = 0; i < n; i++)  // ERREUR: i < n au lieu de i <= n - m
    {
        int j;
        for (j = 0; j < m; j++)
        {
            if (text[i + j] != pattern[j])  // Acces hors limites possible
                break;
        }
        if (j == m)
            return i;
    }
    return -1;
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **algorithmes de chaines** sont fondamentaux en informatique:

1. **Pattern matching** - Trouver un motif dans un texte
2. **Preprocessing** - Precalculer des informations pour accelerer la recherche
3. **Rolling hash** - Calculer des hash incrementaux en O(1)
4. **Programmation dynamique** - Resoudre LCS et edit distance optimalement

### 5.2 Complexites comparees

```
+------------------+-------------+-------------+-----------+
| Algorithme       | Preprocessing | Recherche  | Espace    |
+------------------+-------------+-------------+-----------+
| Naive            | O(1)        | O(n*m)      | O(1)      |
| KMP              | O(m)        | O(n)        | O(m)      |
| Rabin-Karp       | O(m)        | O(n) avg    | O(1)      |
|                  |             | O(n*m) pire |           |
| LCS              | -           | O(n*m)      | O(n*m)    |
| Edit Distance    | -           | O(n*m)      | O(n*m)    |
+------------------+-------------+-------------+-----------+

n = longueur du texte
m = longueur du pattern (ou seconde chaine)
```

### 5.3 Visualisation ASCII

```
========================================================
RECHERCHE NAIVE DE PATTERN "ABABC" DANS "ABABDABABC"
========================================================

Text:    A B A B D A B A B C
Pattern: A B A B C
         ^
         Compare position 0

Position 0: ABABD
            ABABC
            ^^^^X  -> Mismatch a index 4

Text:    A B A B D A B A B C
Pattern:   A B A B C
           ^
           Compare position 1

Position 1: BABDA
            ABABC
            X      -> Mismatch a index 0

... continue jusqu'a position 5 ...

Position 5: ABABC
            ABABC
            ^^^^^  -> MATCH!


========================================================
KMP: CONSTRUCTION DE LA TABLE LPS POUR "ABABCABAB"
========================================================

LPS = Longest Proper Prefix which is also Suffix

Pattern: A  B  A  B  C  A  B  A  B
Index:   0  1  2  3  4  5  6  7  8

i=1: pattern[1]=B, pattern[0]=A, B!=A, len=0 -> lps[1]=0
i=2: pattern[2]=A, pattern[0]=A, A==A, len=1 -> lps[2]=1
i=3: pattern[3]=B, pattern[1]=B, B==B, len=2 -> lps[3]=2
i=4: pattern[4]=C, pattern[2]=A, C!=A
     len=lps[1]=0
     pattern[4]=C, pattern[0]=A, C!=A -> lps[4]=0
i=5: pattern[5]=A, pattern[0]=A, A==A, len=1 -> lps[5]=1
i=6: pattern[6]=B, pattern[1]=B, B==B, len=2 -> lps[6]=2
i=7: pattern[7]=A, pattern[2]=A, A==A, len=3 -> lps[7]=3
i=8: pattern[8]=B, pattern[3]=B, B==B, len=4 -> lps[8]=4

Table LPS finale:
Pattern: A  B  A  B  C  A  B  A  B
LPS:     0  0  1  2  0  1  2  3  4


========================================================
RABIN-KARP: ROLLING HASH
========================================================

Text:    "ABCDE"  Pattern: "BCD"
Base:    256      Mod: 101

Hash du pattern "BCD":
  h_p = (B*256^2 + C*256 + D) mod 101
      = (66*65536 + 67*256 + 68) mod 101
      = 4325476 mod 101 = 97

Hash initial "ABC":
  h_t = (A*256^2 + B*256 + C) mod 101
      = (65*65536 + 66*256 + 67) mod 101
      = 4276803 mod 101 = 38

Hash != -> pas de match

Rolling hash pour "BCD":
  h_t = (256 * (h_t - A*256^2) + D) mod 101
      = (256 * (38 - 65*65536 mod 101) + 68) mod 101
      = 97

Hash == -> verification caractere par caractere -> MATCH!


========================================================
EDIT DISTANCE: "CAT" -> "CART"
========================================================

Table DP:

        ""   C    A    R    T
    +----+----+----+----+----+
""  |  0 |  1 |  2 |  3 |  4 |
    +----+----+----+----+----+
C   |  1 |  0 |  1 |  2 |  3 |
    +----+----+----+----+----+
A   |  2 |  1 |  0 |  1 |  2 |
    +----+----+----+----+----+
T   |  3 |  2 |  1 |  1 |  1 |
    +----+----+----+----+----+

Lecture: dp[3][4] = 1

Backtracking:
(3,4) T==T match      -> (2,3)
(2,3) A!=R            -> insert R -> (2,2)
(2,2) A==A match      -> (1,1)
(1,1) C==C match      -> (0,0)

Operations: C(match) A(match) R(insert) T(match)
CAT -> CART = 1 insertion


========================================================
LCS: "AGGTAB" et "GXTXAYB"
========================================================

Table DP:

         ""   G    X    T    X    A    Y    B
     +----+----+----+----+----+----+----+----+
""   |  0 |  0 |  0 |  0 |  0 |  0 |  0 |  0 |
     +----+----+----+----+----+----+----+----+
A    |  0 |  0 |  0 |  0 |  0 |  1 |  1 |  1 |
     +----+----+----+----+----+----+----+----+
G    |  0 |  1 |  1 |  1 |  1 |  1 |  1 |  1 |
     +----+----+----+----+----+----+----+----+
G    |  0 |  1 |  1 |  1 |  1 |  1 |  1 |  1 |
     +----+----+----+----+----+----+----+----+
T    |  0 |  1 |  1 |  2 |  2 |  2 |  2 |  2 |
     +----+----+----+----+----+----+----+----+
A    |  0 |  1 |  1 |  2 |  2 |  3 |  3 |  3 |
     +----+----+----+----+----+----+----+----+
B    |  0 |  1 |  1 |  2 |  2 |  3 |  3 |  4 |
     +----+----+----+----+----+----+----+----+

LCS length = 4

Backtracking:
(6,7) B==B -> add B -> (5,6)
(5,6) A!=Y -> (5,5)
(5,5) A==A -> add A -> (4,4)
(4,4) T!=X -> (3,4)
(3,4) T!=X -> (3,3)
(3,3) T==T -> add T -> (2,2)
(2,2) G!=X -> (1,2)
(1,2) G!=X -> (1,1)
(1,1) G==G -> add G -> (0,0)

LCS = "GTAB"
```

---

## SECTION 7 : QCM

### Question 1
Quelle est la complexite temporelle de l'algorithme KMP pour rechercher un pattern de longueur m dans un texte de longueur n ?

A) O(n * m)
B) O(n + m)
C) O(n * log m)
D) O(n^2)
E) O(m * log n)

**Reponse correcte: B**

**Explication:**
KMP precalcule la table LPS en O(m), puis effectue une seule passe sur le texte en O(n) grace a cette table. La complexite totale est donc O(n + m), ce qui est optimal pour la recherche de pattern. Contrairement a la recherche naive O(n*m), KMP n'a jamais besoin de reculer dans le texte.

### Question 2
Dans l'algorithme de Rabin-Karp, pourquoi doit-on verifier les caracteres un par un meme quand les hash correspondent ?

A) Pour ameliorer les performances
B) Car les hash sont trop lents a calculer
C) A cause des collisions de hash (faux positifs possibles)
D) Pour supporter les patterns avec caracteres speciaux
E) Car le rolling hash ne fonctionne pas avec tous les alphabets

**Reponse correcte: C**

**Explication:**
Le hash utilise dans Rabin-Karp effectue un modulo pour garder les valeurs dans une plage raisonnable. Cela cree la possibilite de collisions: deux chaines differentes peuvent avoir le meme hash (faux positif). La verification caractere par caractere est necessaire pour eliminer ces faux positifs et garantir l'exactitude du resultat.

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.28-a",
  "name": "string_algorithms",
  "language": "c",
  "language_version": "c17",
  "difficulty": 7,
  "xp": 225,
  "complexity": {
    "time": "O(n+m)",
    "space": "O(m)"
  },
  "files": ["string_algorithms.c", "string_algorithms.h"],
  "prerequisites": ["D.0.13", "0.5", "0.4"],
  "concepts": [
    "pattern_matching",
    "kmp_algorithm",
    "rabin_karp",
    "lcs",
    "edit_distance"
  ],
  "tests": {
    "naive_search": {
      "test_file": "test_naive.c",
      "cases": ["single_match", "multiple_matches", "no_match", "empty_pattern"]
    },
    "kmp_search": {
      "test_file": "test_kmp.c",
      "cases": ["lps_table", "single_match", "overlapping_matches"]
    },
    "rabin_karp": {
      "test_file": "test_rabin_karp.c",
      "cases": ["basic", "hash_collision", "multiple_matches"]
    },
    "lcs": {
      "test_file": "test_lcs.c",
      "cases": ["length", "string_reconstruction", "empty_input"]
    },
    "edit_distance": {
      "test_file": "test_edit.c",
      "cases": ["basic", "same_strings", "empty_strings", "operations"]
    }
  },
  "grading": {
    "naive_search": 15,
    "kmp_algorithm": 25,
    "rabin_karp": 20,
    "lcs": 20,
    "edit_distance": 20
  },
  "tags": ["strings", "algorithms", "dynamic_programming", "hashing"]
}
```
