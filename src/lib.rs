//! Remzar Core Library

// The only leniency is to pass the basic; cargo clippy --all-features -- -D warnings
// Only the core modules (files) must be clippy free; as the main rule.

#![forbid(unsafe_code)] // Disallow all `unsafe` in this crate (tightens memory-safety + auditability).
#![cfg_attr(
    not(test),                          // Apply the following lints only for non-test builds (prod/library code).
    deny(
        clippy::all,                    // Deny all stable Clippy lints.
        clippy::unwrap_used,            // Forbid `.unwrap()` 
        clippy::unwrap_in_result,       // Forbid `unwrap()` 
        clippy::expect_used,            // Forbid `.expect()` 
        clippy::panic,                  // Forbid `panic!()` 
        clippy::panic_in_result_fn,     // Forbid panicking inside functions that return Result.
        clippy::todo,                   // Forbid `todo!()` 
        clippy::unimplemented,          // Forbid `unimplemented!()` 
        clippy::dbg_macro,              // Forbid `dbg!()` 
        clippy::wildcard_imports,       // Forbid `use x::*;` 
        clippy::mutable_key_type,       // Forbid map/set keys that can change while hashed/ordered.
        clippy::exit,                   // Forbid process-killing exits; don’t let library/code paths terminate.
        clippy::indexing_slicing,       // Forbid indexing/slicing that can panic (bounds safety).
        clippy::await_holding_lock,     // Forbid awaiting while holding a Mutex/RwLock guard.
        clippy::unreachable,            // Forbid `unreachable!()` 
        clippy::disallowed_methods,     // Forbid specifically banned methods/APIs 
        clippy::disallowed_types,       // Forbid specifically banned types 
        clippy::large_include_file,     // Avoid embedding huge files in the binary by accident.
        clippy::box_collection,         // Avoid Box<Vec/_> patterns that add indirection for no gain.
        clippy::unnecessary_wraps,      // Avoid pointless Result/Option wrapping (can hide logic issues).
        clippy::match_bool,             // Avoid match on bool (often clearer as if/else; fewer mistakes).
        clippy::needless_collect,       // Avoid collecting just to iterate once (perf).
        clippy::result_large_err,       // Avoid returning large error types by value (perf/alloc churn).
        clippy::large_futures,          // Avoid huge async state machines (can bloat memory/stack; perf/DoS-ish).
        clippy::inefficient_to_string,  // Avoid allocations where formatting isn’t needed.
        clippy::integer_division,       // Flags integer division so truncation/rounding behavior.
        clippy::mutex_atomic,           // Flag suspicious Mutex/atomic combinations.
        clippy::lossy_float_literal,    // Flag float literals that lose precision (determinism/accuracy).
        clippy::checked_conversions,    // Encourage checked conversions instead of unchecked casts.
        clippy::float_arithmetic,       // Discourage float math (nondeterminism/rounding differences).
        clippy::modulo_arithmetic,      // Call out `%` (negatives/bias pitfalls).
        clippy::arithmetic_side_effects,// Require explicit overflow behavior for arithmetic.
        clippy::iter_over_hash_type,    // Iterating “over the hash” byte-by-byte (often suspicious / slow).
        clippy::string_slice,           // Discourage potentially-panicky string slicing.
        clippy::eq_op,                  // Catch accidental `x == x` logic bugs.
        clippy::bytes_nth,              // Discourage `.bytes().nth(n)` (O(n); can become DoS-y on large inputs).
        clippy::iter_nth,               // Discourage `.iter().nth(n)` in hot paths (often O(n); repeated use can be O(n²)).
        clippy::shadow_unrelated,       // prevents “same name, different meaning” bugs.
        clippy::let_underscore_must_use,// Don’t ignore must_use.
        clippy::cast_possible_wrap,     // Cast may wrap.
        clippy::cast_sign_loss,         // Cast may drop sign.
        clippy::cast_precision_loss,    // Cast may lose precision.
        clippy::match_same_arms,        // Duplicate match arms.
        clippy::needless_borrow,        // Unnecessary borrow.
        clippy::redundant_clone,        // Unnecessary clone().
        clippy::rc_mutex,               // Flags Rc<Mutex<_>> / Rc<RwLock<_>>: prefer Arc<Mutex<_>> or redesign.
        clippy::readonly_write_lock,    // Warns when taking a write lock but only reading; use read() to avoid needless exclusivity.
        clippy::mutex_integer,          // Flags Mutex<u64>/Mutex<usize>/etc: often better as Atomic* or batched state.
        clippy::vec_box,                // Similar: Vec<Box<T>> often hurts locality/perf.
        clippy::main_recursion,         // Flag recursion involving `main` (can blow stack / hang startup paths).
        clippy::large_const_arrays,     // Prevent huge const arrays inflating binaries / memory (DoS-ish, slow builds).
        clippy::large_stack_frames,     // Catch big stack frames that risk stack overflow (esp. in hot or async paths).
        clippy::fallible_impl_from,     // Prevents implementing `From` for conversions that can fail; use `TryFrom` so failure is explicit.
        clippy::rc_buffer,              // Flags Rc-backed buffer patterns that can cause unexpected cloning/copying in buffer-heavy (P2P) code.
        clippy::implicit_clone,         // Catch hidden clones (helps keep allocations obvious).
        clippy::cast_possible_truncation,  // Cast may truncate.
        clippy::map_entry,                 // Prefer entry() API (avoids double lookups + logic bugs).
        clippy::filter_map_next,           // Prevent inefficient filter_map(...).next() patterns.
        clippy::manual_ok_or,              // Prefer ok_or/ok_or_else over manual match boilerplate.
        clippy::manual_is_ascii_check,     // Prefer built-in ASCII checks (clearer + less error-prone).
        clippy::large_enum_variant,         // Flag enums with huge variants (moves/copies get expensive).
        clippy::large_stack_arrays,         // Prevent big stack allocations (stack overflow / DoS risk).
        clippy::large_types_passed_by_value,// Don’t pass big structs by value (use refs; improves perf).
        clippy::absurd_extreme_comparisons,    // Catch comparisons that can never be true/false (often overflow/type bugs).
        clippy::float_cmp,                     // Safer float comparisons (ideally keep floats out of consensus paths).
        clippy::from_over_into,                // Prefer explicit conversions over implicit Into() (less surprise alloc/copies).
        clippy::collection_is_never_read,      // Catch collections that only grow (potential memory leak/DoS).
        clippy::await_holding_refcell_ref,     // Forbid awaiting while holding RefCell borrows.
        clippy::await_holding_invalid_type,    // Forbid awaiting while holding “guard-like”/unsafe-to-hold types.
        clippy::inconsistent_struct_constructor,  // Enforce consistent struct init style (readability / uniformity).
        clippy::unchecked_time_subtraction,   // Duration subtraction can underflow (time math safety).
        clippy::trivially_copy_pass_by_ref,       // Warns when `Copy` types are passed by reference.
        clippy::suspicious_operation_groupings,   // check math-heavy code.
    )
)]

// --- modules ---
pub mod blockchain;
pub mod commandline;
pub mod consensus;
pub mod cryptography;
pub mod network;
pub mod privacy;
pub mod reorganization;
pub mod runtime;
pub mod storage;
pub mod tokens;
pub mod utility;
