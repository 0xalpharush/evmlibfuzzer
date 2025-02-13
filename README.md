# Fuzzing EVM smart contracts with Libfuzzer because why not

* Certain inviduals with PHD's may consider this a blacbox grammar fuzzer. However, it obviously is only only syntactically correct and not semantically. That is, the fuzzer is aware of available functions and their arguments (and ABI type), but it does not have any clue that in order to reach certain portions of code it must have previously called others. As I do not have the requisited pedigree, I will leave taxionmies to others.
## How to run

Run with REVM instrumented. (Probably not a good idea but it allows use to user `fuzz_mutator` and `fuzz_crossover`).
```bash
mkdir corpus ./build.sh && ./target/debug/evmlibfuzzer corpus
```

Run without instrumetation as a dumb fuzzer and without custom mutations/splicing.
```bash
cargo run
```

Why is it not a good idea to instrument REVM? Well, maybe it is sort of a proxy for interesting behavior e.g. the smart contract calls `SSTORE` and thus REVM's storage functions are reached. However, it is coarse-grained and the byte-level mutations performed by libfuzzer likely don't preserve that it's interesting to call functions that write where another reads (data dependency).