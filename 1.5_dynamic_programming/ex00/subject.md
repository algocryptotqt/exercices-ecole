# Exercise 00: DP Fundamentals

## Concepts Covered
- **1.5.1.i** Solution reconstruction
- **1.5.2.e-g** Space optimization, direction, trade-offs
- **1.5.3.f-j** Decode ways, jump game variants, coin change

## Objective

Master fundamental DP concepts including state definition, transitions, and optimizations.

## Requirements

### Rust Implementation

```rust
pub mod dp_fundamentals {
    // Classic DP problems

    /// Fibonacci with memoization
    pub fn fib_memo(n: u64) -> u64;

    /// Fibonacci with tabulation (O(1) space)
    pub fn fib_tab(n: u64) -> u64;

    /// Climbing stairs: ways to reach top with 1 or 2 steps
    pub fn climb_stairs(n: usize) -> u64;

    /// Climbing stairs with k step options
    pub fn climb_stairs_k(n: usize, k: usize) -> u64;

    /// House robber: max sum of non-adjacent elements
    pub fn house_robber(nums: &[i32]) -> i32;

    /// House robber II: circular arrangement
    pub fn house_robber_circular(nums: &[i32]) -> i32;

    /// Decode ways: count decodings of digit string
    /// '1'->'A', '2'->'B', ..., '26'->'Z'
    pub fn decode_ways(s: &str) -> u64;

    /// Jump game: can we reach the last index?
    pub fn can_jump(nums: &[i32]) -> bool;

    /// Jump game II: minimum jumps to reach last index
    pub fn min_jumps(nums: &[i32]) -> i32;

    /// Coin change: minimum coins for amount
    pub fn coin_change(coins: &[i32], amount: i32) -> i32;

    /// Coin change II: number of ways to make amount
    pub fn coin_change_ways(coins: &[i32], amount: i32) -> i32;

    /// Perfect squares: min squares summing to n
    pub fn perfect_squares(n: i32) -> i32;

    /// Word break: can string be segmented?
    pub fn word_break(s: &str, word_dict: &[&str]) -> bool;

    /// Longest increasing subsequence
    pub fn lis(nums: &[i32]) -> usize;

    /// LIS with O(n log n) using binary search
    pub fn lis_fast(nums: &[i32]) -> usize;

    // With solution reconstruction

    /// Coin change with reconstruction
    pub fn coin_change_path(coins: &[i32], amount: i32) -> Vec<i32>;

    /// LIS with actual subsequence
    pub fn lis_sequence(nums: &[i32]) -> Vec<i32>;

    /// Word break with all valid segmentations
    pub fn word_break_all(s: &str, word_dict: &[&str]) -> Vec<String>;
}
```

### Python Implementation

```python
def fib_memo(n: int) -> int: ...
def fib_tab(n: int) -> int: ...
def climb_stairs(n: int) -> int: ...
def climb_stairs_k(n: int, k: int) -> int: ...
def house_robber(nums: list[int]) -> int: ...
def house_robber_circular(nums: list[int]) -> int: ...
def decode_ways(s: str) -> int: ...
def can_jump(nums: list[int]) -> bool: ...
def min_jumps(nums: list[int]) -> int: ...
def coin_change(coins: list[int], amount: int) -> int: ...
def coin_change_ways(coins: list[int], amount: int) -> int: ...
def perfect_squares(n: int) -> int: ...
def word_break(s: str, word_dict: list[str]) -> bool: ...
def lis(nums: list[int]) -> int: ...
def lis_fast(nums: list[int]) -> int: ...
def coin_change_path(coins: list[int], amount: int) -> list[int]: ...
def lis_sequence(nums: list[int]) -> list[int]: ...
```

## DP Framework

### Steps
1. Define state: What does `dp[i]` represent?
2. Base case: Initial values
3. Transition: How to compute `dp[i]` from previous states
4. Answer: Which `dp[?]` is the final answer?
5. (Optional) Reconstruct solution

### Space Optimization
When `dp[i]` only depends on `dp[i-1]` and `dp[i-2]`:
- Use rolling variables instead of array
- Reduce O(n) space to O(1)

## Test Cases

```rust
#[test]
fn test_fibonacci() {
    assert_eq!(fib_memo(0), 0);
    assert_eq!(fib_memo(1), 1);
    assert_eq!(fib_memo(10), 55);
    assert_eq!(fib_tab(50), 12586269025);
}

#[test]
fn test_climb_stairs() {
    assert_eq!(climb_stairs(2), 2);
    assert_eq!(climb_stairs(3), 3);
    assert_eq!(climb_stairs(5), 8);
}

#[test]
fn test_house_robber() {
    assert_eq!(house_robber(&[1, 2, 3, 1]), 4);
    assert_eq!(house_robber(&[2, 7, 9, 3, 1]), 12);
    assert_eq!(house_robber_circular(&[2, 3, 2]), 3);
}

#[test]
fn test_decode_ways() {
    assert_eq!(decode_ways("12"), 2);  // "AB" or "L"
    assert_eq!(decode_ways("226"), 3);  // "BZ", "VF", "BBF"
    assert_eq!(decode_ways("06"), 0);  // Invalid
}

#[test]
fn test_jump_game() {
    assert!(can_jump(&[2, 3, 1, 1, 4]));
    assert!(!can_jump(&[3, 2, 1, 0, 4]));
    assert_eq!(min_jumps(&[2, 3, 1, 1, 4]), 2);
}

#[test]
fn test_coin_change() {
    assert_eq!(coin_change(&[1, 2, 5], 11), 3);  // 5+5+1
    assert_eq!(coin_change(&[2], 3), -1);
    assert_eq!(coin_change_ways(&[1, 2, 5], 5), 4);
}

#[test]
fn test_lis() {
    assert_eq!(lis(&[10, 9, 2, 5, 3, 7, 101, 18]), 4);
    assert_eq!(lis_fast(&[10, 9, 2, 5, 3, 7, 101, 18]), 4);

    let seq = lis_sequence(&[10, 9, 2, 5, 3, 7, 101, 18]);
    assert_eq!(seq.len(), 4);
    // Could be [2, 3, 7, 101] or [2, 5, 7, 101] etc.
}

#[test]
fn test_reconstruction() {
    let path = coin_change_path(&[1, 2, 5], 11);
    assert_eq!(path.iter().sum::<i32>(), 11);
    assert_eq!(path.len(), 3);
}
```

## Grading

| Criterion | Points |
|-----------|--------|
| Fibonacci (memo + tab + O(1) space) | 10 |
| Climbing stairs | 10 |
| House robber (linear + circular) | 15 |
| Decode ways | 10 |
| Jump game (I + II) | 15 |
| Coin change (min + ways) | 15 |
| LIS (O(n²) + O(n log n)) | 15 |
| Solution reconstruction | 10 |
| **Total** | **100** |

## Files to Submit

### Rust
- `src/lib.rs`
- `Cargo.toml`

### Python
- `dp_fundamentals.py`
