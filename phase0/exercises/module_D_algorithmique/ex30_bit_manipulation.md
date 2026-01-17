# Exercice D.30 : bit_manipulation

**Module :**
D — Algorithmique

**Concept :**
30 — Manipulation de Bits - Operations bit a bit et algorithmes binaires

**Difficulte :**
[*****-----] (5/10)

**Type :**
code

**Tiers :**
2 — Integration de concepts

**Langage :**
C17

**Prerequis :**
- Operateurs bit a bit (&, |, ^, ~, <<, >>)
- Representation binaire des entiers
- Notions de bases numeriques (binaire, hexadecimal)
- Types entiers et leurs tailles

**Domaines :**
Algo, LowLevel, Optimization

**Duree estimee :**
120 min

**XP Base :**
175

**Complexite :**
T[N] O(log n) x S[N] O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| C | `bit_manipulation.c`, `bit_manipulation.h` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| C | malloc, free, printf (pour debug uniquement) |

---

### 1.2 Consigne

#### Section Culture : "La Manipulation de Bits - L'Art du Calcul Binaire"

La **manipulation de bits** (bit manipulation ou bitwise operations) est une technique fondamentale en programmation bas niveau. Elle permet d'effectuer des operations extremement rapides en travaillant directement sur la representation binaire des nombres.

Cette technique est essentielle dans de nombreux domaines :
- Systemes embarques et programmation materielle
- Cryptographie et securite
- Compression de donnees
- Optimisation de performances
- Graphiques et traitement d'images
- Protocoles reseau et parsing de paquets
- Generation de combinaisons et sous-ensembles

Les operations bit a bit sont executees en un seul cycle CPU, les rendant extremement efficaces pour certains algorithmes.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer une bibliotheque complete d'algorithmes de manipulation de bits. Chaque fonction doit exploiter les proprietes des operations binaires pour atteindre une efficacite optimale.

**Operateurs bit a bit en C :**

```
&   AND bit a bit     : 1 & 1 = 1, sinon 0
|   OR bit a bit      : 0 | 0 = 0, sinon 1
^   XOR bit a bit     : bits differents = 1, identiques = 0
~   NOT bit a bit     : inverse tous les bits
<<  Decalage gauche   : multiplie par 2^n
>>  Decalage droite   : divise par 2^n (entiers non signes)
```

**Prototypes :**

```c
// bit_manipulation.h

#ifndef BIT_MANIPULATION_H
#define BIT_MANIPULATION_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// ============================================
// Comptage de bits
// ============================================

/**
 * Compte le nombre de bits a 1 dans un entier (Hamming Weight / Popcount)
 *
 * @param n: l'entier a analyser
 * @return: nombre de bits a 1
 *
 * Exemple: count_set_bits(13) = 3 (13 = 1101 en binaire)
 *
 * Complexity: O(nombre de bits a 1)
 */
int count_set_bits(uint32_t n);

/**
 * Version optimisee avec lookup table
 * Compte les bits a 1 en utilisant une table precalculee
 *
 * @param n: l'entier a analyser
 * @return: nombre de bits a 1
 *
 * Complexity: O(1)
 */
int count_set_bits_fast(uint32_t n);

// ============================================
// Verification de puissance de 2
// ============================================

/**
 * Verifie si un nombre est une puissance de 2
 *
 * @param n: l'entier a verifier
 * @return: true si n est une puissance de 2, false sinon
 *
 * Exemple: is_power_of_two(16) = true (16 = 10000)
 *          is_power_of_two(18) = false (18 = 10010)
 *
 * Note: 0 n'est pas considere comme une puissance de 2
 *
 * Complexity: O(1)
 */
bool is_power_of_two(uint32_t n);

/**
 * Trouve la plus grande puissance de 2 inferieure ou egale a n
 *
 * @param n: l'entier de reference
 * @return: plus grande puissance de 2 <= n, 0 si n = 0
 *
 * Exemple: floor_power_of_two(13) = 8
 *
 * Complexity: O(log n)
 */
uint32_t floor_power_of_two(uint32_t n);

/**
 * Trouve la plus petite puissance de 2 superieure ou egale a n
 *
 * @param n: l'entier de reference
 * @return: plus petite puissance de 2 >= n
 *
 * Exemple: ceil_power_of_two(13) = 16
 *
 * Complexity: O(log n)
 */
uint32_t ceil_power_of_two(uint32_t n);

// ============================================
// Echange sans variable temporaire
// ============================================

/**
 * Echange deux entiers sans utiliser de variable temporaire
 * Utilise la propriete XOR: a ^ a = 0 et a ^ 0 = a
 *
 * @param a: pointeur vers le premier entier
 * @param b: pointeur vers le second entier
 *
 * Note: Ne fonctionne PAS si a et b pointent vers la meme adresse
 *
 * Complexity: O(1)
 */
void swap_xor(int *a, int *b);

// ============================================
// Trouver l'element unique (XOR trick)
// ============================================

/**
 * Trouve l'unique element qui n'apparait qu'une fois
 * Tous les autres elements apparaissent exactement deux fois
 *
 * @param arr: tableau d'entiers
 * @param size: taille du tableau
 * @return: l'element unique
 *
 * Exemple: find_single([2, 3, 2, 4, 3]) = 4
 *
 * Propriete: a ^ a = 0, donc tous les doublons s'annulent
 *
 * Complexity: O(n) temps, O(1) espace
 */
int find_single_number(const int *arr, size_t size);

/**
 * Trouve les deux elements uniques dans un tableau
 * Tous les autres elements apparaissent exactement deux fois
 *
 * @param arr: tableau d'entiers
 * @param size: taille du tableau
 * @param num1: [out] premier element unique
 * @param num2: [out] second element unique
 *
 * Complexity: O(n) temps, O(1) espace
 */
void find_two_single_numbers(const int *arr, size_t size, int *num1, int *num2);

// ============================================
// Inversion de bits
// ============================================

/**
 * Inverse l'ordre des bits d'un entier 32 bits
 *
 * @param n: l'entier a inverser
 * @return: l'entier avec les bits en ordre inverse
 *
 * Exemple: reverse_bits(0b00000010100101000001111010011100)
 *        = 0b00111001011110000010100101000000
 *
 * Complexity: O(log n) avec technique divide and conquer
 */
uint32_t reverse_bits(uint32_t n);

/**
 * Inverse les bits d'un octet (8 bits)
 *
 * @param b: l'octet a inverser
 * @return: l'octet avec les bits en ordre inverse
 *
 * Exemple: reverse_byte(0b10110001) = 0b10001101
 *
 * Complexity: O(1) avec lookup table
 */
uint8_t reverse_byte(uint8_t b);

// ============================================
// Generation de sous-ensembles
// ============================================

/**
 * Genere tous les sous-ensembles d'un ensemble de n elements
 * Les elements sont representes par les indices 0 a n-1
 *
 * @param n: nombre d'elements dans l'ensemble
 * @param count: [out] nombre de sous-ensembles generes (2^n)
 * @return: tableau de masques representant les sous-ensembles
 *          Chaque masque indique quels elements sont inclus
 *
 * Exemple: generate_subsets(3) retourne:
 *   0b000 = {} (ensemble vide)
 *   0b001 = {0}
 *   0b010 = {1}
 *   0b011 = {0, 1}
 *   0b100 = {2}
 *   0b101 = {0, 2}
 *   0b110 = {1, 2}
 *   0b111 = {0, 1, 2}
 *
 * Complexity: O(2^n)
 */
uint32_t *generate_subsets(int n, size_t *count);

/**
 * Itere sur tous les sous-ensembles d'un masque donne
 * (sous-ensembles des bits a 1)
 *
 * @param mask: le masque dont on veut les sous-ensembles
 * @param count: [out] nombre de sous-ensembles
 * @return: tableau des sous-ensembles
 *
 * Exemple: subset_of_mask(0b101) retourne:
 *   0b000, 0b001, 0b100, 0b101
 *
 * Complexity: O(2^popcount(mask))
 */
uint32_t *subset_of_mask(uint32_t mask, size_t *count);

// ============================================
// Operations utilitaires
// ============================================

/**
 * Retourne le bit a la position donnee
 *
 * @param n: l'entier
 * @param pos: position du bit (0 = bit de poids faible)
 * @return: 0 ou 1
 */
int get_bit(uint32_t n, int pos);

/**
 * Met le bit a la position donnee a 1
 *
 * @param n: l'entier
 * @param pos: position du bit
 * @return: l'entier modifie
 */
uint32_t set_bit(uint32_t n, int pos);

/**
 * Met le bit a la position donnee a 0
 *
 * @param n: l'entier
 * @param pos: position du bit
 * @return: l'entier modifie
 */
uint32_t clear_bit(uint32_t n, int pos);

/**
 * Inverse le bit a la position donnee
 *
 * @param n: l'entier
 * @param pos: position du bit
 * @return: l'entier modifie
 */
uint32_t toggle_bit(uint32_t n, int pos);

/**
 * Trouve la position du bit de poids fort (Most Significant Bit)
 *
 * @param n: l'entier (doit etre > 0)
 * @return: position du MSB (0-indexed), -1 si n = 0
 *
 * Exemple: msb_position(12) = 3 (12 = 1100, bit 3 est le MSB)
 */
int msb_position(uint32_t n);

/**
 * Trouve la position du bit de poids faible a 1 (Least Significant Bit)
 *
 * @param n: l'entier (doit etre > 0)
 * @return: position du LSB a 1 (0-indexed), -1 si n = 0
 *
 * Exemple: lsb_position(12) = 2 (12 = 1100, bit 2 est le premier 1)
 */
int lsb_position(uint32_t n);

/**
 * Isole le bit de poids faible a 1
 *
 * @param n: l'entier
 * @return: entier avec uniquement le LSB a 1
 *
 * Exemple: isolate_lsb(12) = 4 (12 = 1100, resultat = 0100)
 */
uint32_t isolate_lsb(uint32_t n);

/**
 * Efface le bit de poids faible a 1
 *
 * @param n: l'entier
 * @return: entier sans son LSB a 1
 *
 * Exemple: clear_lsb(12) = 8 (12 = 1100, resultat = 1000)
 */
uint32_t clear_lsb(uint32_t n);

#endif
```

**Comportements attendus :**

| Operation | Exemple | Resultat | Explication |
|-----------|---------|----------|-------------|
| count_set_bits(13) | 13 = 1101 | 3 | Trois bits a 1 |
| is_power_of_two(16) | 16 = 10000 | true | Un seul bit a 1 |
| is_power_of_two(18) | 18 = 10010 | false | Deux bits a 1 |
| swap_xor(&a, &b) | a=5, b=3 | a=3, b=5 | Echange via XOR |
| find_single([2,3,2]) | - | 3 | XOR annule les doublons |
| reverse_bits(1) | 0x00000001 | 0x80000000 | Bits inverses |
| generate_subsets(2) | n=2 | [{}, {0}, {1}, {0,1}] | 2^2 = 4 sous-ensembles |

**Exemples binaires :**

```
COMPTAGE DE BITS (Hamming Weight):
==================================
n = 29 = 0b11101

Methode naive: parcourir tous les bits
  11101 & 1 = 1 (count = 1)
  1110  & 1 = 0
  111   & 1 = 1 (count = 2)
  11    & 1 = 1 (count = 3)
  1     & 1 = 1 (count = 4)
  0     -> fin

Methode Brian Kernighan: n & (n-1) efface le LSB a 1
  11101 & 11100 = 11100 (count = 1)
  11100 & 11011 = 11000 (count = 2)
  11000 & 10111 = 10000 (count = 3)
  10000 & 01111 = 00000 (count = 4)
  -> Resultat: 4 bits a 1


PUISSANCE DE 2:
===============
Une puissance de 2 n'a qu'un seul bit a 1:
  1   = 0b0001
  2   = 0b0010
  4   = 0b0100
  8   = 0b1000
  16  = 0b10000

Test: n & (n-1) == 0 ?
  16 & 15 = 10000 & 01111 = 00000 = 0 -> OUI
  18 & 17 = 10010 & 10001 = 10000 != 0 -> NON


SWAP AVEC XOR:
==============
a = 5 = 0101
b = 3 = 0011

Etape 1: a = a ^ b
  a = 0101 ^ 0011 = 0110 (6)

Etape 2: b = a ^ b
  b = 0110 ^ 0011 = 0101 (5) <- ancienne valeur de a!

Etape 3: a = a ^ b
  a = 0110 ^ 0101 = 0011 (3) <- ancienne valeur de b!


FIND SINGLE NUMBER:
===================
Tableau: [2, 3, 2, 4, 3]

XOR cumulatif:
  0 ^ 2 = 2
  2 ^ 3 = 1
  1 ^ 2 = 3
  3 ^ 4 = 7
  7 ^ 3 = 4 <- l'unique!

Propriete: a ^ a = 0, donc 2^2 = 0, 3^3 = 0
           0 ^ 0 ^ 4 = 4


GENERATION DE SOUS-ENSEMBLES:
=============================
Ensemble {a, b, c} avec n=3 elements

Masque binaire -> Sous-ensemble:
  000 -> {}
  001 -> {a}
  010 -> {b}
  011 -> {a, b}
  100 -> {c}
  101 -> {a, c}
  110 -> {b, c}
  111 -> {a, b, c}

Total: 2^3 = 8 sous-ensembles
```

---

### 1.3 Prototype

```c
// bit_manipulation.h - Interface complete

#ifndef BIT_MANIPULATION_H
#define BIT_MANIPULATION_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Comptage de bits
int count_set_bits(uint32_t n);
int count_set_bits_fast(uint32_t n);

// Verification puissance de 2
bool is_power_of_two(uint32_t n);
uint32_t floor_power_of_two(uint32_t n);
uint32_t ceil_power_of_two(uint32_t n);

// Echange XOR
void swap_xor(int *a, int *b);

// Trouver element unique
int find_single_number(const int *arr, size_t size);
void find_two_single_numbers(const int *arr, size_t size, int *num1, int *num2);

// Inversion de bits
uint32_t reverse_bits(uint32_t n);
uint8_t reverse_byte(uint8_t b);

// Generation de sous-ensembles
uint32_t *generate_subsets(int n, size_t *count);
uint32_t *subset_of_mask(uint32_t mask, size_t *count);

// Operations utilitaires
int get_bit(uint32_t n, int pos);
uint32_t set_bit(uint32_t n, int pos);
uint32_t clear_bit(uint32_t n, int pos);
uint32_t toggle_bit(uint32_t n, int pos);
int msb_position(uint32_t n);
int lsb_position(uint32_t n);
uint32_t isolate_lsb(uint32_t n);
uint32_t clear_lsb(uint32_t n);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | count_bits_zero | count_set_bits(0) | 0 | 5 | Comptage |
| 2 | count_bits_one | count_set_bits(1) | 1 | 5 | Comptage |
| 3 | count_bits_all | count_set_bits(0xFFFFFFFF) | 32 | 10 | Comptage |
| 4 | count_bits_mixed | count_set_bits(0b10101010) | 4 | 10 | Comptage |
| 5 | power_two_yes | is_power_of_two(64) | true | 10 | Power2 |
| 6 | power_two_no | is_power_of_two(63) | false | 10 | Power2 |
| 7 | power_two_zero | is_power_of_two(0) | false | 5 | Power2 |
| 8 | swap_basic | swap_xor(5, 3) | 3, 5 | 10 | Swap |
| 9 | single_basic | find_single([2,3,2]) | 3 | 15 | Single |
| 10 | single_large | find_single([1..1000000]) | unique | 10 | Single |
| 11 | two_singles | find_two_singles([1,2,1,3,2,5]) | 3, 5 | 15 | Single |
| 12 | reverse_bits_1 | reverse_bits(1) | 0x80000000 | 15 | Reverse |
| 13 | reverse_bits_mixed | reverse_bits(0x12345678) | 0x1E6A2C48 | 10 | Reverse |
| 14 | subsets_empty | generate_subsets(0) | [0] | 10 | Subsets |
| 15 | subsets_three | generate_subsets(3) | 8 elements | 15 | Subsets |
| 16 | subset_mask | subset_of_mask(0b101) | 4 elements | 10 | Subsets |
| 17 | get_set_clear | operations de base | correct | 10 | Utils |
| 18 | msb_lsb | positions bits | correct | 10 | Utils |
| 19 | stress_test | operations intensives | performance OK | 5 | Stress |
| 20 | memory_check | valgrind | no leaks | 5 | Memory |

**Total : 175 points**

---

### 4.2 Tests unitaires

```c
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "bit_manipulation.h"

void test_count_set_bits(void)
{
    assert(count_set_bits(0) == 0);
    assert(count_set_bits(1) == 1);
    assert(count_set_bits(0b1111) == 4);
    assert(count_set_bits(0b10101010) == 4);
    assert(count_set_bits(0xFFFFFFFF) == 32);
    assert(count_set_bits(0x80000001) == 2);

    // Test version rapide
    assert(count_set_bits_fast(0) == 0);
    assert(count_set_bits_fast(0xFFFFFFFF) == 32);

    printf("test_count_set_bits: PASSED\n");
}

void test_power_of_two(void)
{
    assert(is_power_of_two(0) == false);
    assert(is_power_of_two(1) == true);
    assert(is_power_of_two(2) == true);
    assert(is_power_of_two(3) == false);
    assert(is_power_of_two(4) == true);
    assert(is_power_of_two(16) == true);
    assert(is_power_of_two(18) == false);
    assert(is_power_of_two(1024) == true);
    assert(is_power_of_two(0x80000000) == true);

    // Test floor et ceil
    assert(floor_power_of_two(13) == 8);
    assert(floor_power_of_two(16) == 16);
    assert(floor_power_of_two(1) == 1);

    assert(ceil_power_of_two(13) == 16);
    assert(ceil_power_of_two(16) == 16);
    assert(ceil_power_of_two(1) == 1);

    printf("test_power_of_two: PASSED\n");
}

void test_swap_xor(void)
{
    int a = 5, b = 3;
    swap_xor(&a, &b);
    assert(a == 3 && b == 5);

    a = 0; b = -1;
    swap_xor(&a, &b);
    assert(a == -1 && b == 0);

    a = 0x7FFFFFFF; b = 0x80000000;
    swap_xor(&a, &b);
    assert(a == (int)0x80000000 && b == 0x7FFFFFFF);

    printf("test_swap_xor: PASSED\n");
}

void test_find_single_number(void)
{
    int arr1[] = {2, 3, 2};
    assert(find_single_number(arr1, 3) == 3);

    int arr2[] = {4, 1, 2, 1, 2};
    assert(find_single_number(arr2, 5) == 4);

    int arr3[] = {1};
    assert(find_single_number(arr3, 1) == 1);

    int arr4[] = {1, 2, 1, 3, 2, 5};
    int num1, num2;
    find_two_single_numbers(arr4, 6, &num1, &num2);
    assert((num1 == 3 && num2 == 5) || (num1 == 5 && num2 == 3));

    printf("test_find_single_number: PASSED\n");
}

void test_reverse_bits(void)
{
    assert(reverse_bits(0) == 0);
    assert(reverse_bits(1) == 0x80000000);
    assert(reverse_bits(0x80000000) == 1);
    assert(reverse_bits(0xFFFFFFFF) == 0xFFFFFFFF);

    // 0b00000010100101000001111010011100 = 43261596
    // reversed = 0b00111001011110000010100101000000 = 964176192
    assert(reverse_bits(43261596) == 964176192);

    assert(reverse_byte(0b10110001) == 0b10001101);
    assert(reverse_byte(0xFF) == 0xFF);
    assert(reverse_byte(0x00) == 0x00);

    printf("test_reverse_bits: PASSED\n");
}

void test_generate_subsets(void)
{
    size_t count;
    uint32_t *subsets;

    // n = 0: seul le sous-ensemble vide
    subsets = generate_subsets(0, &count);
    assert(count == 1);
    assert(subsets[0] == 0);
    free(subsets);

    // n = 3: 8 sous-ensembles
    subsets = generate_subsets(3, &count);
    assert(count == 8);
    // Verifier que tous les masques de 0 a 7 sont presents
    int found[8] = {0};
    for (size_t i = 0; i < count; i++)
    {
        assert(subsets[i] < 8);
        found[subsets[i]] = 1;
    }
    for (int i = 0; i < 8; i++)
        assert(found[i] == 1);
    free(subsets);

    // Test subset_of_mask
    subsets = subset_of_mask(0b101, &count);
    assert(count == 4);  // 0b000, 0b001, 0b100, 0b101
    free(subsets);

    printf("test_generate_subsets: PASSED\n");
}

void test_bit_operations(void)
{
    // get_bit
    assert(get_bit(0b1010, 0) == 0);
    assert(get_bit(0b1010, 1) == 1);
    assert(get_bit(0b1010, 3) == 1);

    // set_bit
    assert(set_bit(0b1010, 0) == 0b1011);
    assert(set_bit(0b1010, 2) == 0b1110);

    // clear_bit
    assert(clear_bit(0b1010, 1) == 0b1000);
    assert(clear_bit(0b1010, 3) == 0b0010);

    // toggle_bit
    assert(toggle_bit(0b1010, 0) == 0b1011);
    assert(toggle_bit(0b1010, 1) == 0b1000);

    // msb_position
    assert(msb_position(1) == 0);
    assert(msb_position(8) == 3);
    assert(msb_position(12) == 3);
    assert(msb_position(0x80000000) == 31);

    // lsb_position
    assert(lsb_position(1) == 0);
    assert(lsb_position(8) == 3);
    assert(lsb_position(12) == 2);

    // isolate_lsb
    assert(isolate_lsb(12) == 4);
    assert(isolate_lsb(0b1010) == 0b0010);

    // clear_lsb
    assert(clear_lsb(12) == 8);
    assert(clear_lsb(0b1010) == 0b1000);

    printf("test_bit_operations: PASSED\n");
}

int main(void)
{
    test_count_set_bits();
    test_power_of_two();
    test_swap_xor();
    test_find_single_number();
    test_reverse_bits();
    test_generate_subsets();
    test_bit_operations();

    printf("\nAll tests PASSED!\n");
    return 0;
}
```

---

### 4.3 Solution de reference

```c
// bit_manipulation.c - Implementation complete

#include "bit_manipulation.h"
#include <stdlib.h>

// ============================================
// Table de lookup pour comptage rapide (8 bits)
// ============================================

static const uint8_t bit_count_table[256] = {
    0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4,
    1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,
    1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,
    2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
    1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,
    2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
    2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
    3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
    1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,
    2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
    2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
    3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
    2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
    3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
    3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
    4,5,5,6,5,6,6,7,5,6,6,7,6,7,7,8
};

// ============================================
// Comptage de bits (Hamming Weight)
// ============================================

int count_set_bits(uint32_t n)
{
    int count = 0;

    // Methode Brian Kernighan: n & (n-1) efface le LSB a 1
    while (n)
    {
        n &= (n - 1);
        count++;
    }

    return count;
}

int count_set_bits_fast(uint32_t n)
{
    // Utilise la lookup table pour chaque octet
    return bit_count_table[n & 0xFF] +
           bit_count_table[(n >> 8) & 0xFF] +
           bit_count_table[(n >> 16) & 0xFF] +
           bit_count_table[(n >> 24) & 0xFF];
}

// ============================================
// Verification puissance de 2
// ============================================

bool is_power_of_two(uint32_t n)
{
    // Une puissance de 2 n'a qu'un seul bit a 1
    // n & (n-1) efface ce bit unique -> resultat 0
    // Cas special: 0 n'est pas une puissance de 2
    return n != 0 && (n & (n - 1)) == 0;
}

uint32_t floor_power_of_two(uint32_t n)
{
    if (n == 0)
        return 0;

    // Propager le bit de poids fort vers la droite
    n |= (n >> 1);
    n |= (n >> 2);
    n |= (n >> 4);
    n |= (n >> 8);
    n |= (n >> 16);

    // Maintenant n a tous les bits a 1 depuis le MSB
    // (n + 1) >> 1 donne la puissance de 2
    return (n + 1) >> 1;
}

uint32_t ceil_power_of_two(uint32_t n)
{
    if (n == 0)
        return 1;

    // Si deja une puissance de 2, retourner n
    if (is_power_of_two(n))
        return n;

    // Sinon, prendre floor et multiplier par 2
    return floor_power_of_two(n) << 1;
}

// ============================================
// Echange XOR
// ============================================

void swap_xor(int *a, int *b)
{
    if (a == b)
        return;  // Securite: ne fonctionne pas si meme adresse

    *a = *a ^ *b;
    *b = *a ^ *b;  // b = (a ^ b) ^ b = a
    *a = *a ^ *b;  // a = (a ^ b) ^ a = b
}

// ============================================
// Trouver element unique
// ============================================

int find_single_number(const int *arr, size_t size)
{
    int result = 0;

    // XOR de tous les elements
    // Les doublons s'annulent: a ^ a = 0
    for (size_t i = 0; i < size; i++)
    {
        result ^= arr[i];
    }

    return result;
}

void find_two_single_numbers(const int *arr, size_t size, int *num1, int *num2)
{
    // Phase 1: XOR de tous les elements = num1 ^ num2
    int xor_all = 0;
    for (size_t i = 0; i < size; i++)
    {
        xor_all ^= arr[i];
    }

    // Phase 2: Trouver un bit ou num1 et num2 different
    // Ce bit est a 1 dans xor_all
    // Utiliser le LSB a 1: xor_all & (-xor_all)
    int diff_bit = xor_all & (-xor_all);

    // Phase 3: Separer les nombres en deux groupes
    // selon ce bit
    *num1 = 0;
    *num2 = 0;

    for (size_t i = 0; i < size; i++)
    {
        if (arr[i] & diff_bit)
        {
            *num1 ^= arr[i];
        }
        else
        {
            *num2 ^= arr[i];
        }
    }
}

// ============================================
// Inversion de bits
// ============================================

uint32_t reverse_bits(uint32_t n)
{
    // Methode divide and conquer
    // Etape 1: echanger les moities de 16 bits
    n = (n >> 16) | (n << 16);

    // Etape 2: echanger les quartets adjacents de 8 bits
    n = ((n & 0xFF00FF00) >> 8) | ((n & 0x00FF00FF) << 8);

    // Etape 3: echanger les paires adjacentes de 4 bits
    n = ((n & 0xF0F0F0F0) >> 4) | ((n & 0x0F0F0F0F) << 4);

    // Etape 4: echanger les paires adjacentes de 2 bits
    n = ((n & 0xCCCCCCCC) >> 2) | ((n & 0x33333333) << 2);

    // Etape 5: echanger les bits adjacents
    n = ((n & 0xAAAAAAAA) >> 1) | ((n & 0x55555555) << 1);

    return n;
}

// Table de lookup pour inverser un octet
static const uint8_t reverse_byte_table[256] = {
    0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0,
    0x10, 0x90, 0x50, 0xD0, 0x30, 0xB0, 0x70, 0xF0,
    0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8, 0x68, 0xE8,
    0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8,
    0x04, 0x84, 0x44, 0xC4, 0x24, 0xA4, 0x64, 0xE4,
    0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4,
    0x0C, 0x8C, 0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC,
    0x1C, 0x9C, 0x5C, 0xDC, 0x3C, 0xBC, 0x7C, 0xFC,
    0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2,
    0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2, 0x72, 0xF2,
    0x0A, 0x8A, 0x4A, 0xCA, 0x2A, 0xAA, 0x6A, 0xEA,
    0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA,
    0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6,
    0x16, 0x96, 0x56, 0xD6, 0x36, 0xB6, 0x76, 0xF6,
    0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE,
    0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE,
    0x01, 0x81, 0x41, 0xC1, 0x21, 0xA1, 0x61, 0xE1,
    0x11, 0x91, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1,
    0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9,
    0x19, 0x99, 0x59, 0xD9, 0x39, 0xB9, 0x79, 0xF9,
    0x05, 0x85, 0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5,
    0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5,
    0x0D, 0x8D, 0x4D, 0xCD, 0x2D, 0xAD, 0x6D, 0xED,
    0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD, 0x7D, 0xFD,
    0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3,
    0x13, 0x93, 0x53, 0xD3, 0x33, 0xB3, 0x73, 0xF3,
    0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB,
    0x1B, 0x9B, 0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB,
    0x07, 0x87, 0x47, 0xC7, 0x27, 0xA7, 0x67, 0xE7,
    0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7,
    0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF, 0x6F, 0xEF,
    0x1F, 0x9F, 0x5F, 0xDF, 0x3F, 0xBF, 0x7F, 0xFF
};

uint8_t reverse_byte(uint8_t b)
{
    return reverse_byte_table[b];
}

// ============================================
// Generation de sous-ensembles
// ============================================

uint32_t *generate_subsets(int n, size_t *count)
{
    if (n < 0 || n > 31)
    {
        *count = 0;
        return NULL;
    }

    // Il y a 2^n sous-ensembles
    *count = (size_t)1 << n;

    uint32_t *subsets = malloc(*count * sizeof(uint32_t));
    if (subsets == NULL)
    {
        *count = 0;
        return NULL;
    }

    // Chaque nombre de 0 a 2^n - 1 represente un sous-ensemble
    for (size_t i = 0; i < *count; i++)
    {
        subsets[i] = (uint32_t)i;
    }

    return subsets;
}

uint32_t *subset_of_mask(uint32_t mask, size_t *count)
{
    // Compter le nombre de bits a 1 dans le masque
    int num_bits = count_set_bits(mask);
    *count = (size_t)1 << num_bits;

    uint32_t *subsets = malloc(*count * sizeof(uint32_t));
    if (subsets == NULL)
    {
        *count = 0;
        return NULL;
    }

    // Enumerer tous les sous-ensembles du masque
    // Technique: subset = (subset - 1) & mask
    size_t idx = 0;
    uint32_t subset = mask;

    do
    {
        subsets[idx++] = subset;
        subset = (subset - 1) & mask;
    } while (subset != mask);

    return subsets;
}

// ============================================
// Operations utilitaires
// ============================================

int get_bit(uint32_t n, int pos)
{
    return (n >> pos) & 1;
}

uint32_t set_bit(uint32_t n, int pos)
{
    return n | ((uint32_t)1 << pos);
}

uint32_t clear_bit(uint32_t n, int pos)
{
    return n & ~((uint32_t)1 << pos);
}

uint32_t toggle_bit(uint32_t n, int pos)
{
    return n ^ ((uint32_t)1 << pos);
}

int msb_position(uint32_t n)
{
    if (n == 0)
        return -1;

    int pos = 0;

    // Recherche binaire de la position du MSB
    if (n >= 0x10000) { pos += 16; n >>= 16; }
    if (n >= 0x100)   { pos += 8;  n >>= 8;  }
    if (n >= 0x10)    { pos += 4;  n >>= 4;  }
    if (n >= 0x4)     { pos += 2;  n >>= 2;  }
    if (n >= 0x2)     { pos += 1;            }

    return pos;
}

int lsb_position(uint32_t n)
{
    if (n == 0)
        return -1;

    int pos = 0;

    // Utiliser la technique n & (-n) pour isoler le LSB
    // puis trouver sa position
    if (!(n & 0x0000FFFF)) { pos += 16; n >>= 16; }
    if (!(n & 0x000000FF)) { pos += 8;  n >>= 8;  }
    if (!(n & 0x0000000F)) { pos += 4;  n >>= 4;  }
    if (!(n & 0x00000003)) { pos += 2;  n >>= 2;  }
    if (!(n & 0x00000001)) { pos += 1;            }

    return pos;
}

uint32_t isolate_lsb(uint32_t n)
{
    // n & (-n) isole le bit de poids faible a 1
    // -n en complement a deux = ~n + 1
    return n & (-n);
}

uint32_t clear_lsb(uint32_t n)
{
    // n & (n-1) efface le bit de poids faible a 1
    return n & (n - 1);
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Comptage de bits incorrect) : Boucle sur tous les bits au lieu de Brian Kernighan**

```c
// MUTANT A: Comptage incorrect - off by one
int count_set_bits(uint32_t n)
{
    int count = 0;

    // ERREUR: condition while (n > 0) au lieu de while (n)
    // Probleme avec les nombres negatifs en signed
    while (n > 0)
    {
        count += n & 1;
        n >>= 1;  // ERREUR: signed right shift peut propager le bit de signe
    }

    return count;
}
```
**Pourquoi faux :** En utilisant `n > 0` avec un type signe, les nombres negatifs ne seraient jamais traites. Avec un decalage a droite signe (`>>`), le bit de signe peut etre propage, causant une boucle infinie pour les valeurs negatives.

---

**Mutant B (Puissance de 2 sans cas zero) : Oubli du cas n=0**

```c
// MUTANT B: Oubli du cas n = 0
bool is_power_of_two(uint32_t n)
{
    // ERREUR: pas de verification n != 0
    // 0 & (0-1) = 0 & 0xFFFFFFFF = 0
    return (n & (n - 1)) == 0;
}
```
**Pourquoi faux :** `0 & (0-1) = 0 & 0xFFFFFFFF = 0`, donc la fonction retournerait `true` pour n=0. Or, 0 n'est pas une puissance de 2 par definition mathematique (2^k >= 1 pour tout k >= 0).

---

**Mutant C (Swap XOR avec meme pointeur) : Crash si a == b**

```c
// MUTANT C: Pas de verification si meme adresse
void swap_xor(int *a, int *b)
{
    // ERREUR: Si a == b, alors *a ^= *a donne 0
    *a = *a ^ *b;  // Si a == b: *a = *a ^ *a = 0
    *b = *a ^ *b;  // *b = 0 ^ 0 = 0
    *a = *a ^ *b;  // *a = 0 ^ 0 = 0
    // Resultat: les deux valeurs sont 0!
}
```
**Pourquoi faux :** Si les deux pointeurs pointent vers la meme adresse memoire, `*a ^ *a = 0`. Les operations suivantes donnent toutes 0, detruisant la valeur originale.

---

**Mutant D (Find single avec addition) : Utilisation de + au lieu de XOR**

```c
// MUTANT D: Addition au lieu de XOR
int find_single_number(const int *arr, size_t size)
{
    int result = 0;

    // ERREUR: addition au lieu de XOR
    for (size_t i = 0; i < size; i++)
    {
        result += arr[i];  // ERREUR: les doublons ne s'annulent pas
    }

    // Tentative de correction: diviser par 2?
    // Non, ca ne fonctionne pas car on ne connait pas la somme des doublons
    return result;
}
```
**Pourquoi faux :** L'addition ne permet pas d'annuler les doublons. Par exemple, `[2, 3, 2]` donne `2 + 3 + 2 = 7`, pas `3`. La propriete `a ^ a = 0` est unique au XOR.

---

**Mutant E (Reverse bits incomplet) : Oubli d'une etape**

```c
// MUTANT E: Oubli de la derniere etape
uint32_t reverse_bits(uint32_t n)
{
    // Etape 1: echanger les moities de 16 bits
    n = (n >> 16) | (n << 16);

    // Etape 2: echanger les quartets adjacents de 8 bits
    n = ((n & 0xFF00FF00) >> 8) | ((n & 0x00FF00FF) << 8);

    // Etape 3: echanger les paires adjacentes de 4 bits
    n = ((n & 0xF0F0F0F0) >> 4) | ((n & 0x0F0F0F0F) << 4);

    // ERREUR: etapes 4 et 5 manquantes
    // Les bits a l'interieur de chaque groupe de 4 ne sont pas inverses

    return n;  // Resultat incorrect pour la plupart des entrees
}
```
**Pourquoi faux :** L'algorithme divide-and-conquer necessite 5 etapes pour inverser completement 32 bits. En oubliant les deux dernieres etapes, les bits a l'interieur de chaque quartet (4 bits) restent dans leur ordre original.

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

La **manipulation de bits** illustre plusieurs concepts fondamentaux :

1. **Representation binaire** - Comprendre comment les nombres sont stockes en memoire
2. **Operations O(1)** - Les operations bit a bit sont executees en un cycle CPU
3. **Astuces mathematiques** - Proprietes de XOR, AND, OR exploitables algorithmiquement
4. **Optimisation** - Remplacer des operations couteuses par des operations bit a bit

### 5.2 Representation binaire des entiers

```
REPRESENTATION BINAIRE (32 bits non signes):
============================================

Decimal    Hexadecimal    Binaire (8 bits affiche)
-------    -----------    ------------------------
    0      0x00000000     00000000
    1      0x00000001     00000001
    2      0x00000002     00000010
    3      0x00000003     00000011
    4      0x00000004     00000100
    7      0x00000007     00000111
    8      0x00000008     00001000
   15      0x0000000F     00001111
   16      0x00000010     00010000
  255      0x000000FF     11111111

Puissances de 2 (un seul bit a 1):
    1 = 2^0 = 00000001
    2 = 2^1 = 00000010
    4 = 2^2 = 00000100
    8 = 2^3 = 00001000
   16 = 2^4 = 00010000


OPERATEURS BIT A BIT:
=====================

AND (&) - Bit a 1 seulement si les deux sont a 1:
    1010 & 1100 = 1000

    Utilisations:
    - Masquer des bits: n & 0x0F extrait les 4 bits de poids faible
    - Tester un bit: (n & (1 << pos)) != 0
    - Effacer des bits: n & ~mask

OR (|) - Bit a 1 si au moins un est a 1:
    1010 | 1100 = 1110

    Utilisations:
    - Mettre des bits a 1: n | mask
    - Combiner des flags: FLAGS = FLAG_A | FLAG_B

XOR (^) - Bit a 1 si les bits sont differents:
    1010 ^ 1100 = 0110

    Proprietes:
    - a ^ 0 = a (element neutre)
    - a ^ a = 0 (auto-inverse)
    - a ^ b ^ a = b (permet d'annuler)
    - Commutatif et associatif

NOT (~) - Inverse tous les bits:
    ~1010 = 0101 (sur 4 bits)
    ~1010 = 11111111111111111111111111110101 (sur 32 bits)

LEFT SHIFT (<<) - Decale vers la gauche, ajoute des 0:
    1010 << 2 = 101000
    Equivalent a: n * 2^k

RIGHT SHIFT (>>) - Decale vers la droite:
    1010 >> 2 = 0010
    Pour unsigned: equivalent a n / 2^k


TECHNIQUES CLASSIQUES:
======================

1. Tester le bit a la position pos:
   (n >> pos) & 1
   ou
   (n & (1 << pos)) != 0

2. Mettre le bit a la position pos a 1:
   n | (1 << pos)

3. Mettre le bit a la position pos a 0:
   n & ~(1 << pos)

4. Inverser le bit a la position pos:
   n ^ (1 << pos)

5. Isoler le bit de poids faible a 1:
   n & (-n)
   ou
   n & (~n + 1)

6. Effacer le bit de poids faible a 1:
   n & (n - 1)

   Exemple: 1100 & 1011 = 1000

7. Verifier si puissance de 2:
   n != 0 && (n & (n - 1)) == 0

8. Compter les bits a 1 (Brian Kernighan):
   count = 0
   while (n):
       n = n & (n - 1)
       count++
```

### 5.3 Visualisation ASCII

```
COMPTAGE DE BITS - METHODE BRIAN KERNIGHAN:
===========================================

Principe: n & (n-1) efface le bit de poids faible a 1

n = 52 = 0b110100

Iteration 1:
  n     = 110100
  n-1   = 110011
  n&(n-1)= 110000  -> count = 1

Iteration 2:
  n     = 110000
  n-1   = 101111
  n&(n-1)= 100000  -> count = 2

Iteration 3:
  n     = 100000
  n-1   = 011111
  n&(n-1)= 000000  -> count = 3

Resultat: 52 a 3 bits a 1

Complexite: O(nombre de bits a 1), pas O(32)


VERIFICATION PUISSANCE DE 2:
============================

Puissance de 2: exactement UN bit a 1

n = 16 = 0b10000
n-1    = 0b01111
n&(n-1)= 0b00000 = 0  -> OUI, puissance de 2

n = 18 = 0b10010
n-1    = 0b10001
n&(n-1)= 0b10000 != 0 -> NON, pas puissance de 2

Explication visuelle:
  Puissance de 2:  100...000 (un seul 1)
  Moins 1:         011...111 (tous les bits apres deviennent 1)
  AND:             000...000 (aucun bit en commun!)


SWAP XOR - DEMONSTRATION:
=========================

Initial: a = 5 (0101), b = 3 (0011)

Etape 1: a = a ^ b
         a = 0101 ^ 0011 = 0110 (6)

         Etat: a = 6, b = 3

Etape 2: b = a ^ b
         b = 0110 ^ 0011 = 0101 (5)

         Mathematiquement: b = (a_orig ^ b_orig) ^ b_orig
                            = a_orig ^ (b_orig ^ b_orig)
                            = a_orig ^ 0
                            = a_orig

         Etat: a = 6, b = 5

Etape 3: a = a ^ b
         a = 0110 ^ 0101 = 0011 (3)

         Mathematiquement: a = (a_orig ^ b_orig) ^ a_orig
                            = b_orig

         Etat: a = 3, b = 5

Resultat: les valeurs sont echangees!

ATTENTION: Si a et b pointent vers la meme adresse:
  a = a ^ a = 0
  b = 0 ^ 0 = 0
  a = 0 ^ 0 = 0
  -> Les deux valeurs sont perdues!


FIND SINGLE NUMBER - XOR MAGIC:
===============================

Tableau: [4, 1, 2, 1, 2]
Trouver l'element qui apparait une seule fois.

XOR cumulatif:
  0 ^ 4 = 100       = 4
  4 ^ 1 = 101       = 5
  5 ^ 2 = 111       = 7
  7 ^ 1 = 110       = 6
  6 ^ 2 = 100       = 4  <- l'unique!

Pourquoi ca marche:
  XOR est commutatif et associatif:
  4 ^ 1 ^ 2 ^ 1 ^ 2 = 4 ^ (1 ^ 1) ^ (2 ^ 2)
                    = 4 ^ 0 ^ 0
                    = 4


REVERSE BITS - DIVIDE AND CONQUER:
==================================

Inverser les 32 bits de n = 0x12345678

Representation binaire:
  0001 0010 0011 0100 0101 0110 0111 1000

Etape 1: Echanger les deux moities de 16 bits
  Avant: [0001 0010 0011 0100] [0101 0110 0111 1000]
  Apres: [0101 0110 0111 1000] [0001 0010 0011 0100]
  = 0x56781234

Etape 2: Echanger les octets adjacents
  Avant: [0101 0110] [0111 1000] [0001 0010] [0011 0100]
  Apres: [0111 1000] [0101 0110] [0011 0100] [0001 0010]
  = 0x78563412

Etape 3: Echanger les quartets (4 bits) adjacents
  Avant: [0111] [1000] [0101] [0110] [0011] [0100] [0001] [0010]
  Apres: [1000] [0111] [0110] [0101] [0100] [0011] [0010] [0001]
  = 0x87654321

Etape 4: Echanger les paires de bits adjacentes
  (continue le meme principe)

Etape 5: Echanger les bits adjacents
  Resultat final inverse


GENERATION DE SOUS-ENSEMBLES:
=============================

Ensemble {a, b, c} avec indices {0, 1, 2}

Chaque entier de 0 a 2^n - 1 represente un sous-ensemble:

Binaire   Decimal   Sous-ensemble
-------   -------   -------------
  000       0       {} (vide)
  001       1       {a}
  010       2       {b}
  011       3       {a, b}
  100       4       {c}
  101       5       {a, c}
  110       6       {b, c}
  111       7       {a, b, c}

Pour enumerer les elements d'un sous-ensemble (masque):
  for (int i = 0; i < n; i++)
      if (mask & (1 << i))
          element i est present


SOUS-ENSEMBLES D'UN MASQUE:
===========================

Masque = 0b101 (elements 0 et 2)

Technique: subset = (subset - 1) & mask

  subset = 101
  (101 - 1) & 101 = 100 & 101 = 100
  (100 - 1) & 101 = 011 & 101 = 001
  (001 - 1) & 101 = 000 & 101 = 000
  (000 - 1) & 101 = 111 & 101 = 101 (retour au debut)

Sous-ensembles: 101, 100, 001, 000
En decimal: 5, 4, 1, 0
```

---

## SECTION 7 : QCM

### Question 1 (3 points)

Quelle est la valeur de l'expression `n & (n - 1)` pour n = 12 (en binaire: 1100) ?

- A) 0
- B) 4
- C) 8
- D) 11
- E) 12

**Reponse correcte : C**

**Explication :** L'operation `n & (n - 1)` efface le bit de poids faible a 1.
- n = 12 = 0b1100
- n - 1 = 11 = 0b1011
- n & (n-1) = 0b1100 & 0b1011 = 0b1000 = 8

Le bit a la position 2 (valeur 4), qui etait le bit de poids faible a 1 dans 12, a ete efface. Cette technique est fondamentale pour le comptage de bits (Brian Kernighan) et la verification de puissance de 2.

---

### Question 2 (3 points)

Pourquoi la technique de swap avec XOR (`a ^= b; b ^= a; a ^= b;`) ne fonctionne-t-elle pas si `a` et `b` pointent vers la meme adresse memoire ?

- A) Le XOR n'est pas defini pour les pointeurs
- B) L'operation cause un debordement d'entier
- C) `a ^ a` donne 0, detruisant la valeur originale
- D) Les operations ne sont pas atomiques
- E) Le compilateur optimise et supprime les operations

**Reponse correcte : C**

**Explication :** Si `a` et `b` pointent vers la meme variable memoire :
1. `*a ^= *b` devient `*a ^= *a` = 0 (car x ^ x = 0)
2. `*b ^= *a` devient `0 ^= 0` = 0
3. `*a ^= *b` devient `0 ^= 0` = 0

La propriete d'auto-annulation du XOR (`x ^ x = 0`) detruit la valeur originale des la premiere operation. C'est pourquoi il faut toujours verifier `if (a != b)` avant d'utiliser cette technique.

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.30",
  "name": "bit_manipulation",
  "version": "1.0.0",
  "language": "c",
  "language_version": "c17",
  "difficulty": 5,
  "xp_base": 175,
  "estimated_time_minutes": 120,
  "complexity": {
    "time": "O(log n)",
    "space": "O(1)"
  },
  "files": {
    "required": ["bit_manipulation.c", "bit_manipulation.h"],
    "provided": ["main.c", "Makefile"],
    "tests": ["test_bit_manipulation.c"]
  },
  "compilation": {
    "command": "gcc -Wall -Wextra -Werror -std=c17 -o bit_manipulation bit_manipulation.c main.c",
    "flags": ["-Wall", "-Wextra", "-Werror", "-std=c17"]
  },
  "tests": {
    "unit_tests": "test_bit_manipulation.c",
    "moulinette": {
      "timeout_seconds": 5,
      "memory_check": true,
      "valgrind_flags": ["--leak-check=full", "--error-exitcode=1"]
    }
  },
  "topics": [
    "bit_manipulation",
    "bitwise_operators",
    "binary_representation",
    "hamming_weight",
    "popcount",
    "xor_tricks",
    "power_of_two",
    "subset_generation",
    "low_level_optimization"
  ],
  "prerequisites": [
    "0.3",
    "0.5"
  ],
  "learning_objectives": [
    "Comprendre la representation binaire des entiers",
    "Maitriser les operateurs bit a bit (&, |, ^, ~, <<, >>)",
    "Implementer des algorithmes efficaces avec manipulation de bits",
    "Utiliser les proprietes du XOR pour resoudre des problemes",
    "Generer des sous-ensembles avec des masques binaires",
    "Optimiser le code avec des operations O(1)"
  ],
  "grading": {
    "auto_grade": true,
    "total_points": 175,
    "categories": {
      "count_set_bits": 25,
      "power_of_two": 25,
      "swap_xor": 15,
      "find_single": 30,
      "reverse_bits": 30,
      "generate_subsets": 25,
      "utility_operations": 20,
      "memory_management": 5
    }
  },
  "hints": [
    "n & (n-1) efface le bit de poids faible a 1",
    "n & (-n) isole le bit de poids faible a 1",
    "XOR: a ^ a = 0 et a ^ 0 = a",
    "Pour inverser des bits, utilisez divide and conquer",
    "Chaque entier de 0 a 2^n-1 represente un sous-ensemble"
  ]
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
