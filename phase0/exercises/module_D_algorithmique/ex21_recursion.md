# Exercice D.0.21-a : recursion

**Module :**
D.0.21 — Recursion Avancee

**Concept :**
a-e — Recursion, tail recursion, memoization, divide and conquer

**Difficulte :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.11 (recursion basics)

**Domaines :**
Algo

**Duree estimee :**
180 min

**XP Base :**
250

**Complexite :**
Variable

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `recursion.c`
- `recursion.h`

### 1.2 Consigne

Implementer des algorithmes recursifs avances.

**Ta mission :**

```c
// Factorielle classique
long factorial(int n);

// Factorielle tail-recursive
long factorial_tail(int n, long acc);

// Fibonacci naif
long fib_naive(int n);

// Fibonacci avec memoization
long fib_memo(int n);

// Puissance rapide (exponentiation)
long power(long base, int exp);

// GCD (Euclide recursif)
int gcd(int a, int b);

// Tower of Hanoi
void hanoi(int n, char from, char to, char aux, void (*move)(int, char, char));

// Permutations
void permutations(char *str, int l, int r, void (*callback)(char *));

// Binary search recursive
int binary_search_rec(int *arr, int target, int low, int high);

// Sum of array recursive
int sum_recursive(int *arr, int n);
```

**Comportement:**

1. `factorial(5)` -> 120
2. `fib_memo(50)` -> 12586269025 (efficace)
3. `power(2, 10)` -> 1024
4. `gcd(48, 18)` -> 6

**Exemples:**
```
factorial(5) = 5 * 4 * 3 * 2 * 1 = 120

fib_naive(10):
fib(10) = fib(9) + fib(8)
       = (fib(8) + fib(7)) + (fib(7) + fib(6))
       ... beaucoup de recalculs!

power(2, 10):
2^10 = (2^5)^2 = ((2^2)^2 * 2)^2 = ...
Seulement O(log n) multiplications!

gcd(48, 18):
gcd(48, 18) = gcd(18, 48 % 18) = gcd(18, 12)
           = gcd(12, 18 % 12) = gcd(12, 6)
           = gcd(6, 12 % 6) = gcd(6, 0) = 6
```

### 1.3 Prototype

```c
// recursion.h
#ifndef RECURSION_H
#define RECURSION_H

long factorial(int n);
long factorial_tail(int n, long acc);
long fib_naive(int n);
long fib_memo(int n);
long power(long base, int exp);
int gcd(int a, int b);
void hanoi(int n, char from, char to, char aux, void (*move)(int, char, char));
void permutations(char *str, int l, int r, void (*callback)(char *));
int binary_search_rec(int *arr, int target, int low, int high);
int sum_recursive(int *arr, int n);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | factorial(10) | 3628800 | 10 |
| T02 | fib_memo(50) | correct | 15 |
| T03 | power(2, 10) | 1024 | 15 |
| T04 | gcd(48, 18) | 6 | 15 |
| T05 | hanoi(3) | correct moves | 15 |
| T06 | binary_search_rec | correct | 15 |
| T07 | edge cases | handled | 15 |

### 4.3 Solution de reference

```c
#include <stdlib.h>
#include "recursion.h"

long factorial(int n)
{
    if (n <= 1)
        return 1;
    return n * factorial(n - 1);
}

long factorial_tail(int n, long acc)
{
    if (n <= 1)
        return acc;
    return factorial_tail(n - 1, n * acc);
}

long fib_naive(int n)
{
    if (n <= 1)
        return n;
    return fib_naive(n - 1) + fib_naive(n - 2);
}

static long fib_helper(int n, long *memo)
{
    if (memo[n] != -1)
        return memo[n];

    if (n <= 1)
        memo[n] = n;
    else
        memo[n] = fib_helper(n - 1, memo) + fib_helper(n - 2, memo);

    return memo[n];
}

long fib_memo(int n)
{
    if (n < 0)
        return 0;

    long *memo = malloc((n + 1) * sizeof(long));
    for (int i = 0; i <= n; i++)
        memo[i] = -1;

    long result = fib_helper(n, memo);
    free(memo);
    return result;
}

long power(long base, int exp)
{
    if (exp == 0)
        return 1;
    if (exp < 0)
        return 0;  // Simplification pour entiers

    if (exp % 2 == 0)
    {
        long half = power(base, exp / 2);
        return half * half;
    }
    else
    {
        return base * power(base, exp - 1);
    }
}

int gcd(int a, int b)
{
    if (a < 0) a = -a;
    if (b < 0) b = -b;

    if (b == 0)
        return a;
    return gcd(b, a % b);
}

void hanoi(int n, char from, char to, char aux, void (*move)(int, char, char))
{
    if (n == 1)
    {
        move(1, from, to);
        return;
    }

    hanoi(n - 1, from, aux, to, move);
    move(n, from, to);
    hanoi(n - 1, aux, to, from, move);
}

static void swap_char(char *a, char *b)
{
    char temp = *a;
    *a = *b;
    *b = temp;
}

void permutations(char *str, int l, int r, void (*callback)(char *))
{
    if (l == r)
    {
        callback(str);
        return;
    }

    for (int i = l; i <= r; i++)
    {
        swap_char(&str[l], &str[i]);
        permutations(str, l + 1, r, callback);
        swap_char(&str[l], &str[i]);  // Backtrack
    }
}

int binary_search_rec(int *arr, int target, int low, int high)
{
    if (low > high)
        return -1;

    int mid = low + (high - low) / 2;

    if (arr[mid] == target)
        return mid;
    else if (arr[mid] > target)
        return binary_search_rec(arr, target, low, mid - 1);
    else
        return binary_search_rec(arr, target, mid + 1, high);
}

int sum_recursive(int *arr, int n)
{
    if (n <= 0)
        return 0;
    return arr[n - 1] + sum_recursive(arr, n - 1);
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: factorial sans cas de base
long factorial(int n)
{
    return n * factorial(n - 1);  // Recursion infinie!
}

// MUTANT 2: fib_memo sans initialisation
long fib_memo(int n)
{
    long *memo = malloc((n + 1) * sizeof(long));
    // Pas d'initialisation a -1
    // memo contient des valeurs aleatoires
    return fib_helper(n, memo);
}

// MUTANT 3: power sans cas exp == 0
long power(long base, int exp)
{
    if (exp % 2 == 0)
    {
        long half = power(base, exp / 2);  // exp/2 peut etre 0!
        return half * half;
    }
    return base * power(base, exp - 1);
}

// MUTANT 4: gcd sans gestion des negatifs
int gcd(int a, int b)
{
    if (b == 0)
        return a;
    return gcd(b, a % b);
    // gcd(-12, 8) donne resultat negatif
}

// MUTANT 5: binary_search_rec overflow
int binary_search_rec(int *arr, int target, int low, int high)
{
    if (low > high)
        return -1;
    int mid = (low + high) / 2;  // Overflow si low+high > INT_MAX
    // ...
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

La **recursion avancee**:

1. **Cas de base** - Condition d'arret
2. **Tail recursion** - Optimisable par le compilateur
3. **Memoization** - Eviter les recalculs
4. **Divide and conquer** - Diviser le probleme

### 5.3 Visualisation ASCII

```
RECURSION TREE pour fib_naive(5):

         fib(5)
        /      \
     fib(4)    fib(3)
     /   \      /   \
  fib(3) fib(2) fib(2) fib(1)
   /  \
fib(2) fib(1)

Beaucoup de noeuds dupliques!
fib(3) calcule 2x, fib(2) calcule 3x...

MEMOIZATION:
memo = [-1, -1, -1, -1, -1, -1]
fib_memo(5):
  fib(4): memo[4] = ?
    fib(3): memo[3] = ?
      fib(2): memo[2] = fib(1) + fib(0) = 1
      fib(1): memo[1] = 1
    memo[3] = 1 + 1 = 2
    fib(2): memo[2] = 1 (CACHE HIT!)
  memo[4] = 2 + 1 = 3
  fib(3): memo[3] = 2 (CACHE HIT!)
memo[5] = 3 + 2 = 5

TAIL RECURSION:
factorial(5) = 5 * factorial(4)  <- Doit garder 5 sur la stack
             = 5 * 4 * factorial(3)
             = ...

factorial_tail(5, 1) = factorial_tail(4, 5)  <- Pas besoin de stack!
                     = factorial_tail(3, 20)
                     = factorial_tail(2, 60)
                     = factorial_tail(1, 120)
                     = 120
```

---

## SECTION 7 : QCM

### Question 1
Quelle est la complexite de fib_naive(n) ?

A) O(n)
B) O(n log n)
C) O(2^n)
D) O(n^2)
E) O(log n)

**Reponse correcte: C**

### Question 2
Qu'est-ce que la tail recursion ?

A) Recursion a la fin du fichier
B) Recursion ou l'appel recursif est la derniere operation
C) Recursion sur la queue d'une liste
D) Recursion inverse
E) Recursion sans cas de base

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.21-a",
  "name": "recursion",
  "language": "c",
  "language_version": "c17",
  "files": ["recursion.c", "recursion.h"],
  "tests": {
    "basic": "recursion_basic_tests",
    "memoization": "memo_tests",
    "advanced": "advanced_recursion_tests"
  }
}
```
