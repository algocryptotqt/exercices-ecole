# Exercise 01: Linear & Sequence DP

## Concepts Covered
- **1.5.3.e-l** Linear DP patterns, optimal substructure
- **1.5.4.d-m** LIS, LCS, Edit Distance, sequence alignment

## Objective

Master fundamental sequence dynamic programming problems.

## Requirements

### Rust Implementation

```rust
pub mod linear_dp {
    /// Maximum subarray sum (Kadane's algorithm)
    pub fn max_subarray(arr: &[i64]) -> i64;

    /// Maximum subarray with indices
    pub fn max_subarray_indices(arr: &[i64]) -> (i64, usize, usize);

    /// Maximum circular subarray sum
    pub fn max_circular_subarray(arr: &[i64]) -> i64;

    /// Maximum product subarray
    pub fn max_product_subarray(arr: &[i64]) -> i64;

    /// House robber (non-adjacent elements)
    pub fn house_robber(houses: &[i64]) -> i64;

    /// House robber II (circular array)
    pub fn house_robber_circular(houses: &[i64]) -> i64;

    /// Paint house (k colors, adjacent different)
    pub fn paint_house(costs: &[Vec<i64>]) -> i64;

    /// Jump game: can reach end?
    pub fn can_jump(jumps: &[usize]) -> bool;

    /// Minimum jumps to reach end
    pub fn min_jumps(jumps: &[usize]) -> Option<usize>;

    /// Decode ways (count interpretations of digit string)
    pub fn decode_ways(s: &str) -> i64;
}

pub mod sequence_dp {
    /// Longest Increasing Subsequence - O(n log n)
    pub fn lis(arr: &[i64]) -> usize;

    /// LIS with actual subsequence
    pub fn lis_sequence(arr: &[i64]) -> Vec<i64>;

    /// Longest Non-Decreasing Subsequence
    pub fn lnds(arr: &[i64]) -> usize;

    /// Number of LIS
    pub fn count_lis(arr: &[i64]) -> i64;

    /// Longest Bitonic Subsequence
    pub fn longest_bitonic(arr: &[i64]) -> usize;

    /// Longest Common Subsequence - O(nm)
    pub fn lcs(a: &[i32], b: &[i32]) -> usize;

    /// LCS with actual subsequence
    pub fn lcs_sequence<T: Eq + Clone>(a: &[T], b: &[T]) -> Vec<T>;

    /// LCS of multiple sequences
    pub fn lcs_multiple(seqs: &[Vec<i32>]) -> usize;

    /// Shortest Common Supersequence
    pub fn scs(a: &[i32], b: &[i32]) -> Vec<i32>;

    /// Edit Distance (Levenshtein)
    pub fn edit_distance(s1: &str, s2: &str) -> usize;

    /// Edit distance with operations
    pub fn edit_operations(s1: &str, s2: &str) -> Vec<EditOp>;

    #[derive(Debug, Clone)]
    pub enum EditOp {
        Insert(usize, char),
        Delete(usize),
        Replace(usize, char),
        Match,
    }

    /// Weighted edit distance
    pub fn weighted_edit_distance(
        s1: &str,
        s2: &str,
        insert_cost: i64,
        delete_cost: i64,
        replace_cost: i64,
    ) -> i64;

    /// Longest Palindromic Subsequence
    pub fn lps(s: &str) -> usize;

    /// Longest Palindromic Substring
    pub fn longest_palindrome_substring(s: &str) -> String;

    /// Minimum insertions to make palindrome
    pub fn min_insertions_palindrome(s: &str) -> usize;
}

pub mod partition_dp {
    /// Partition into K equal sum subsets
    pub fn partition_equal_sum(arr: &[i64], k: usize) -> bool;

    /// Partition into two equal sum subsets
    pub fn partition_two_equal(arr: &[i64]) -> bool;

    /// Minimum partition difference
    pub fn min_partition_diff(arr: &[i64]) -> i64;

    /// Word break: can s be segmented into dictionary words?
    pub fn word_break(s: &str, dict: &[String]) -> bool;

    /// All word break segmentations
    pub fn word_break_all(s: &str, dict: &[String]) -> Vec<String>;

    /// Palindrome partitioning: minimum cuts
    pub fn min_palindrome_cuts(s: &str) -> usize;

    /// All palindrome partitions
    pub fn palindrome_partitions(s: &str) -> Vec<Vec<String>>;
}
```

### Python Implementation

```python
from typing import List, Optional, Tuple

def max_subarray(arr: List[int]) -> int: ...
def max_subarray_indices(arr: List[int]) -> Tuple[int, int, int]: ...
def house_robber(houses: List[int]) -> int: ...
def can_jump(jumps: List[int]) -> bool: ...
def min_jumps(jumps: List[int]) -> Optional[int]: ...

def lis(arr: List[int]) -> int: ...
def lis_sequence(arr: List[int]) -> List[int]: ...
def count_lis(arr: List[int]) -> int: ...

def lcs(a: List[int], b: List[int]) -> int: ...
def lcs_sequence(a: List, b: List) -> List: ...

def edit_distance(s1: str, s2: str) -> int: ...
def lps(s: str) -> int: ...
def longest_palindrome_substring(s: str) -> str: ...

def partition_equal_sum(arr: List[int], k: int) -> bool: ...
def word_break(s: str, dict: List[str]) -> bool: ...
def min_palindrome_cuts(s: str) -> int: ...
```

## Test Cases

```rust
#[test]
fn test_max_subarray() {
    assert_eq!(max_subarray(&[-2, 1, -3, 4, -1, 2, 1, -5, 4]), 6);
    assert_eq!(max_subarray(&[-1, -2, -3]), -1);
    assert_eq!(max_subarray(&[1, 2, 3]), 6);
}

#[test]
fn test_house_robber() {
    assert_eq!(house_robber(&[1, 2, 3, 1]), 4);
    assert_eq!(house_robber(&[2, 7, 9, 3, 1]), 12);
    assert_eq!(house_robber_circular(&[2, 3, 2]), 3);
}

#[test]
fn test_jump_game() {
    assert!(can_jump(&[2, 3, 1, 1, 4]));
    assert!(!can_jump(&[3, 2, 1, 0, 4]));
    assert_eq!(min_jumps(&[2, 3, 1, 1, 4]), Some(2));
}

#[test]
fn test_lis() {
    assert_eq!(lis(&[10, 9, 2, 5, 3, 7, 101, 18]), 4);
    assert_eq!(lis(&[0, 1, 0, 3, 2, 3]), 4);
    assert_eq!(lis(&[7, 7, 7, 7]), 1);

    let seq = lis_sequence(&[10, 9, 2, 5, 3, 7, 101, 18]);
    assert_eq!(seq.len(), 4);
}

#[test]
fn test_count_lis() {
    assert_eq!(count_lis(&[1, 3, 5, 4, 7]), 2);  // [1,3,5,7] and [1,3,4,7]
}

#[test]
fn test_lcs() {
    assert_eq!(lcs(&[1, 2, 3, 4, 5], &[2, 3, 5, 6]), 3);

    let seq = lcs_sequence(&['a', 'b', 'c', 'd', 'e'], &['a', 'c', 'e']);
    assert_eq!(seq, vec!['a', 'c', 'e']);
}

#[test]
fn test_edit_distance() {
    assert_eq!(edit_distance("horse", "ros"), 3);
    assert_eq!(edit_distance("intention", "execution"), 5);
    assert_eq!(edit_distance("", "abc"), 3);
}

#[test]
fn test_lps() {
    assert_eq!(lps("bbbab"), 4);  // "bbbb"
    assert_eq!(lps("cbbd"), 2);   // "bb"
}

#[test]
fn test_longest_palindrome_substring() {
    let s = longest_palindrome_substring("babad");
    assert!(s == "bab" || s == "aba");

    assert_eq!(longest_palindrome_substring("cbbd"), "bb");
}

#[test]
fn test_word_break() {
    let dict = vec!["leet".into(), "code".into()];
    assert!(word_break("leetcode", &dict));

    let dict2 = vec!["cats".into(), "dog".into(), "sand".into(), "and".into(), "cat".into()];
    assert!(word_break("catsandog", &dict2) == false);
}

#[test]
fn test_palindrome_partition() {
    assert_eq!(min_palindrome_cuts("aab"), 1);  // "aa" | "b"
    assert_eq!(min_palindrome_cuts("ab"), 1);
    assert_eq!(min_palindrome_cuts("aaa"), 0);

    let partitions = palindrome_partitions("aab");
    assert!(partitions.contains(&vec!["a".to_string(), "a".to_string(), "b".to_string()]));
    assert!(partitions.contains(&vec!["aa".to_string(), "b".to_string()]));
}

#[test]
fn test_partition_equal() {
    assert!(partition_two_equal(&[1, 5, 11, 5]));
    assert!(!partition_two_equal(&[1, 2, 3, 5]));
    assert!(partition_equal_sum(&[4, 3, 2, 3, 5, 2, 1], 4));
}

#[test]
fn test_scs() {
    let scs = scs(&[1, 3, 5], &[2, 3, 4]);
    // One valid SCS: [1, 2, 3, 4, 5] or [1, 2, 3, 5, 4]
    assert!(scs.len() == 5);
}
```

## Grading

| Criterion | Points |
|-----------|--------|
| Kadane's algorithm variants | 10 |
| House robber variants | 10 |
| LIS (O(n log n)) | 15 |
| LCS and variants | 15 |
| Edit distance | 15 |
| Palindrome DP | 15 |
| Partition problems | 15 |
| Edge cases | 5 |
| **Total** | **100** |
