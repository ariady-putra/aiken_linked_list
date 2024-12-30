use aiken/fuzz
use fuzz_util/fuzzer
use linkedlist/utils

fn not_zero(i: Int) -> Bool {
  i != 0
}

test div_ceil_prop(
  (a, b) via fuzzer.tuple(fuzz.int(), fuzz.such_that(fuzz.int(), not_zero)),
) {
  utils.div_ceil(a, b) == a / b + if a % b == 0 {
    0
  } else {
    1
  }
}

// Test Case 1
// Test when a is divisible by b
test div_ceil_1() {
  utils.div_ceil(10, 5) == 2
}

// Test Case 2
// Test when a is not divisible by b
test div_ceil_2() {
  utils.div_ceil(7, 3) == 3
}

// Test Case 3
// Test when a is 0
test div_ceil_3() {
  utils.div_ceil(0, 5) == 0
}

// Test Case 4
// Test when b is 1
test div_ceil_4() {
  utils.div_ceil(10, 1) == 10
}
