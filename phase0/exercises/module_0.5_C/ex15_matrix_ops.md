# Exercice 0.5.15-a : matrix_ops

**Module :**
0.5.15 — Tableaux Multidimensionnels

**Concept :**
a-c — 2D arrays, Row-major order, Matrix operations

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.14 (array_basics)

**Domaines :**
Algo, Math

**Duree estimee :**
180 min

**XP Base :**
200

**Complexite :**
T3 O(n^2) x S2 O(n^2)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `matrix_ops.c`
- `matrix_ops.h`

**Fonctions autorisees :**
- Aucune fonction de bibliotheque requise

### 1.2 Consigne

Implementer des operations sur des matrices (tableaux 2D).

**Ta mission :**

Pour des matrices de taille fixe 3x3:

```c
#define MATRIX_SIZE 3

// Initialiser une matrice a zero
void matrix_zero(int m[MATRIX_SIZE][MATRIX_SIZE]);

// Initialiser une matrice identite
void matrix_identity(int m[MATRIX_SIZE][MATRIX_SIZE]);

// Copier une matrice
void matrix_copy(int dest[MATRIX_SIZE][MATRIX_SIZE],
                 int src[MATRIX_SIZE][MATRIX_SIZE]);

// Addition de matrices
void matrix_add(int result[MATRIX_SIZE][MATRIX_SIZE],
                int a[MATRIX_SIZE][MATRIX_SIZE],
                int b[MATRIX_SIZE][MATRIX_SIZE]);

// Transposition de matrice
void matrix_transpose(int result[MATRIX_SIZE][MATRIX_SIZE],
                      int m[MATRIX_SIZE][MATRIX_SIZE]);

// Trace de la matrice (somme diagonale)
int matrix_trace(int m[MATRIX_SIZE][MATRIX_SIZE]);

// Verifier si la matrice est symetrique
int matrix_is_symmetric(int m[MATRIX_SIZE][MATRIX_SIZE]);

// Multiplication scalaire
void matrix_scalar_mult(int m[MATRIX_SIZE][MATRIX_SIZE], int scalar);
```

**Comportement:**

1. `matrix_zero(m)`: Remplit m de zeros
2. `matrix_identity(m)`: Cree matrice identite (1 sur diagonale, 0 ailleurs)
3. `matrix_add(result, a, b)`: result = a + b
4. `matrix_transpose(result, m)`: result[i][j] = m[j][i]
5. `matrix_trace(m)`: Retourne m[0][0] + m[1][1] + m[2][2]
6. `matrix_is_symmetric(m)`: 1 si m[i][j] == m[j][i] pour tout i,j
7. `matrix_scalar_mult(m, k)`: Multiplie chaque element par k

**Exemples:**
```
Matrice identite 3x3:
1 0 0
0 1 0
0 0 1

matrix_trace(identite) -> 3

A = 1 2 3    B = 9 8 7
    4 5 6        6 5 4
    7 8 9        3 2 1

matrix_add(R, A, B):
R = 10 10 10
    10 10 10
    10 10 10

matrix_transpose(R, A):
R = 1 4 7
    2 5 8
    3 6 9
```

### 1.3 Prototype

```c
// matrix_ops.h
#ifndef MATRIX_OPS_H
#define MATRIX_OPS_H

#define MATRIX_SIZE 3

void matrix_zero(int m[MATRIX_SIZE][MATRIX_SIZE]);
void matrix_identity(int m[MATRIX_SIZE][MATRIX_SIZE]);
void matrix_copy(int dest[MATRIX_SIZE][MATRIX_SIZE],
                 int src[MATRIX_SIZE][MATRIX_SIZE]);
void matrix_add(int result[MATRIX_SIZE][MATRIX_SIZE],
                int a[MATRIX_SIZE][MATRIX_SIZE],
                int b[MATRIX_SIZE][MATRIX_SIZE]);
void matrix_transpose(int result[MATRIX_SIZE][MATRIX_SIZE],
                      int m[MATRIX_SIZE][MATRIX_SIZE]);
int matrix_trace(int m[MATRIX_SIZE][MATRIX_SIZE]);
int matrix_is_symmetric(int m[MATRIX_SIZE][MATRIX_SIZE]);
void matrix_scalar_mult(int m[MATRIX_SIZE][MATRIX_SIZE], int scalar);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | matrix_zero | all zeros | 10 |
| T02 | matrix_identity | diag=1, rest=0 | 10 |
| T03 | matrix_trace(identity) | 3 | 10 |
| T04 | matrix_add test | correct sum | 15 |
| T05 | matrix_transpose test | correct transpose | 15 |
| T06 | matrix_is_symmetric(symmetric) | 1 | 10 |
| T07 | matrix_is_symmetric(non_sym) | 0 | 10 |
| T08 | matrix_scalar_mult by 2 | all doubled | 10 |
| T09 | Compilation | No warnings | 10 |

### 4.3 Solution de reference

```c
#include "matrix_ops.h"

void matrix_zero(int m[MATRIX_SIZE][MATRIX_SIZE])
{
    for (int i = 0; i < MATRIX_SIZE; i++)
    {
        for (int j = 0; j < MATRIX_SIZE; j++)
        {
            m[i][j] = 0;
        }
    }
}

void matrix_identity(int m[MATRIX_SIZE][MATRIX_SIZE])
{
    for (int i = 0; i < MATRIX_SIZE; i++)
    {
        for (int j = 0; j < MATRIX_SIZE; j++)
        {
            m[i][j] = (i == j) ? 1 : 0;
        }
    }
}

void matrix_copy(int dest[MATRIX_SIZE][MATRIX_SIZE],
                 int src[MATRIX_SIZE][MATRIX_SIZE])
{
    for (int i = 0; i < MATRIX_SIZE; i++)
    {
        for (int j = 0; j < MATRIX_SIZE; j++)
        {
            dest[i][j] = src[i][j];
        }
    }
}

void matrix_add(int result[MATRIX_SIZE][MATRIX_SIZE],
                int a[MATRIX_SIZE][MATRIX_SIZE],
                int b[MATRIX_SIZE][MATRIX_SIZE])
{
    for (int i = 0; i < MATRIX_SIZE; i++)
    {
        for (int j = 0; j < MATRIX_SIZE; j++)
        {
            result[i][j] = a[i][j] + b[i][j];
        }
    }
}

void matrix_transpose(int result[MATRIX_SIZE][MATRIX_SIZE],
                      int m[MATRIX_SIZE][MATRIX_SIZE])
{
    for (int i = 0; i < MATRIX_SIZE; i++)
    {
        for (int j = 0; j < MATRIX_SIZE; j++)
        {
            result[i][j] = m[j][i];
        }
    }
}

int matrix_trace(int m[MATRIX_SIZE][MATRIX_SIZE])
{
    int trace = 0;
    for (int i = 0; i < MATRIX_SIZE; i++)
    {
        trace += m[i][i];
    }
    return trace;
}

int matrix_is_symmetric(int m[MATRIX_SIZE][MATRIX_SIZE])
{
    for (int i = 0; i < MATRIX_SIZE; i++)
    {
        for (int j = i + 1; j < MATRIX_SIZE; j++)
        {
            if (m[i][j] != m[j][i])
                return 0;
        }
    }
    return 1;
}

void matrix_scalar_mult(int m[MATRIX_SIZE][MATRIX_SIZE], int scalar)
{
    for (int i = 0; i < MATRIX_SIZE; i++)
    {
        for (int j = 0; j < MATRIX_SIZE; j++)
        {
            m[i][j] *= scalar;
        }
    }
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Indices inverses pour transpose
void matrix_transpose(int result[MATRIX_SIZE][MATRIX_SIZE],
                      int m[MATRIX_SIZE][MATRIX_SIZE])
{
    for (int i = 0; i < MATRIX_SIZE; i++)
    {
        for (int j = 0; j < MATRIX_SIZE; j++)
        {
            result[i][j] = m[i][j];  // Pas d'inversion!
        }
    }
}

// MUTANT 2: Identity met 1 partout
void matrix_identity(int m[MATRIX_SIZE][MATRIX_SIZE])
{
    for (int i = 0; i < MATRIX_SIZE; i++)
    {
        for (int j = 0; j < MATRIX_SIZE; j++)
        {
            m[i][j] = 1;  // Devrait etre (i == j) ? 1 : 0
        }
    }
}

// MUTANT 3: Transpose in-place ecrase les donnees
void matrix_transpose_inplace(int m[MATRIX_SIZE][MATRIX_SIZE])
{
    for (int i = 0; i < MATRIX_SIZE; i++)
    {
        for (int j = 0; j < MATRIX_SIZE; j++)
        {
            int temp = m[i][j];
            m[i][j] = m[j][i];  // Ecrase avant d'utiliser
            m[j][i] = temp;     // Donnee deja ecrasee!
        }
    }
}

// MUTANT 4: Symmetric verifie mal
int matrix_is_symmetric(int m[MATRIX_SIZE][MATRIX_SIZE])
{
    for (int i = 0; i < MATRIX_SIZE; i++)
    {
        for (int j = 0; j < MATRIX_SIZE; j++)  // Devrait etre j = i+1
        {
            if (m[i][j] != m[j][i])
                return 0;
        }
    }
    return 1;  // Fonctionne mais inefficace
}

// MUTANT 5: Off-by-one dans trace
int matrix_trace(int m[MATRIX_SIZE][MATRIX_SIZE])
{
    int trace = 0;
    for (int i = 1; i <= MATRIX_SIZE; i++)  // Commence a 1, va trop loin
    {
        trace += m[i][i];  // Acces hors limites
    }
    return trace;
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **tableaux 2D** en C:
- **Declaration** : `int m[ROWS][COLS];`
- **Acces** : `m[row][col]` ou `m[i][j]`
- **Row-major order** : les lignes sont contigues en memoire
- **Passage aux fonctions** : la deuxieme dimension doit etre specifiee

### 5.3 Visualisation ASCII

```
Declaration: int m[3][4];

Logiquement:
        col 0   col 1   col 2   col 3
      +-------+-------+-------+-------+
row 0 | m[0][0]| m[0][1]| m[0][2]| m[0][3]|
      +-------+-------+-------+-------+
row 1 | m[1][0]| m[1][1]| m[1][2]| m[1][3]|
      +-------+-------+-------+-------+
row 2 | m[2][0]| m[2][1]| m[2][2]| m[2][3]|
      +-------+-------+-------+-------+

En memoire (row-major):
+-------+-------+-------+-------+-------+-------+-------+...
| [0][0]| [0][1]| [0][2]| [0][3]| [1][0]| [1][1]| [1][2]|
+-------+-------+-------+-------+-------+-------+-------+...
<------- row 0 --------><------- row 1 -------->

Matrice identite 3x3:
+---+---+---+
| 1 | 0 | 0 |
+---+---+---+
| 0 | 1 | 0 |
+---+---+---+
| 0 | 0 | 1 |
+---+---+---+
```

### 5.5 Cours Complet

#### Declaration et initialisation

```c
// Declaration
int matrix[3][3];

// Initialisation complete
int m[2][3] = {
    {1, 2, 3},
    {4, 5, 6}
};

// Initialisation a zero
int zeros[3][3] = {0};
```

#### Passage aux fonctions

```c
// La deuxieme dimension DOIT etre specifiee
void process(int m[3][4]);  // OK
void process(int m[][4]);   // OK aussi
// void process(int m[][]);  // ERREUR!

// Avec define
#define COLS 4
void process(int m[][COLS], int rows);
```

#### Parcours standard

```c
for (int i = 0; i < rows; i++)
{
    for (int j = 0; j < cols; j++)
    {
        // m[i][j] = element a ligne i, colonne j
    }
}
```

---

## SECTION 7 : QCM

### Question 1
Comment sont stockees les matrices en C ?

A) Column-major order
B) Row-major order
C) Random order
D) Diagonal first
E) Depend du compilateur

**Reponse correcte: B**

### Question 2
Quelle declaration de parametre est correcte pour `int m[3][4]` ?

A) void f(int m[][])
B) void f(int m[3][])
C) void f(int m[][4])
D) void f(int **m)
E) void f(int m[])

**Reponse correcte: C**

### Question 3
Dans `int m[2][3]`, combien d'entiers sont stockes ?

A) 2
B) 3
C) 5
D) 6
E) 8

**Reponse correcte: D**

### Question 4
Quelle est la trace d'une matrice identite 4x4 ?

A) 0
B) 1
C) 4
D) 16
E) Undefined

**Reponse correcte: C**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.15-a",
  "name": "matrix_ops",
  "language": "c",
  "language_version": "c17",
  "files": ["matrix_ops.c", "matrix_ops.h"],
  "tests": {
    "zero": "all_zeros_check",
    "identity": "diag_ones_check",
    "add": "matrix_sum_test",
    "transpose": "transpose_verification",
    "symmetric": [[1,2,2],[2,1,3],[2,3,1]]
  }
}
```
