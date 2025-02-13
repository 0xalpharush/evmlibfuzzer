#![no_main]
use alloy_primitives::{Address, TxKind, U256};
use alloy_sol_types::SolCall;
use arbitrary::{Arbitrary, Unstructured};
use foundry_contracts::target::Target;
use libfuzzer_sys::{fuzz_crossover, fuzz_mutator, fuzz_target, fuzzer_mutate, Corpus};
use rand::{rngs::StdRng, Rng, SeedableRng};

use bincode;
use revm::{
    context::{setters::ContextSetters, Context, TxEnv},
    context_interface::result::{ExecutionResult, Output},
    database_interface::EmptyDB,
    ExecuteCommitEvm, ExecuteEvm, MainBuilder, MainContext,
};
use revm_database::CacheDB;

#[derive(Arbitrary, Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
enum Action {
    F(U256),
    G(U256),
    H,
}

fuzz_target!(|orig: &[u8]| -> Corpus {
    let data: Vec<Action> = match bincode::deserialize(orig) {
        Ok(data) => data,
        Err(_) => {
            let mut u1 = Unstructured::new(orig);
            u1.arbitrary::<Vec<Action>>().unwrap()
        }
    };

    let bytecode = &Target::BYTECODE;
    let caller = Address::new([0x00; 20]);
    let db = CacheDB::new(EmptyDB::new());
    let ctx = Context::mainnet().with_db(db).modify_tx_chained(|tx| {
        tx.caller = caller;
        tx.kind = TxKind::Create;
        tx.data = bytecode.clone();
    });

    let mut evm = ctx.build_mainnet();

    let ref_tx = evm.transact_commit_previous().unwrap();
    let ExecutionResult::Success {
        output: Output::Create(_, Some(address)),
        ..
    } = ref_tx
    else {
        panic!("Failed to create contract: {ref_tx:#?}");
    };

    for action in data {
        let call = match action {
            Action::F(x) => Target::fCall { x: x }.abi_encode(),
            Action::G(y) => Target::gCall { y: y }.abi_encode(),
            Action::H => Target::hCall {}.abi_encode(),
        };
        let nonce = evm.journaled_state.load_account(caller).unwrap().info.nonce;
        evm.set_tx(TxEnv {
            caller: caller,
            kind: TxKind::Call(address),
            data: call.into(),
            nonce: nonce,
            ..Default::default()
        });
        let _ = evm.transact_commit_previous().unwrap();

        // Invariant check
        let call = Target::invariant_checkCall {}.abi_encode();
        let nonce = evm.journaled_state.load_account(caller).unwrap().info.nonce;
        evm.set_tx(TxEnv {
            caller: caller,
            kind: TxKind::Call(address),
            data: call.into(),
            nonce: nonce,
            ..Default::default()
        });
        let ref_tx = evm.transact_previous().unwrap();
        let value = match ref_tx.result {
            ExecutionResult::Success {
                output: Output::Call(value),
                ..
            } => value,
            result => {
                panic!("Failed to execute invariant check: {result:#?}");
            }
        };

        let success = Target::invariant_checkCall::abi_decode_returns(&value, false).unwrap();

        if !success._0 {
            panic!("Invariant check failed");
        }
    }
    Corpus::Keep
});

fuzz_crossover!(|data1: &[u8], data2: &[u8], out: &mut [u8], seed: u32| {
    let mut gen = StdRng::seed_from_u64(seed.into());

    let mut data1: Vec<Action> = match bincode::deserialize(data1) {
        Ok(data) => data,
        Err(_) => {
            let mut u1 = Unstructured::new(data1);
            u1.arbitrary::<Vec<Action>>().unwrap()
        }
    };

    let mut data2: Vec<Action> = match bincode::deserialize(data2) {
        Ok(data) => data,
        Err(_) => {
            let mut u2 = Unstructured::new(data2);
            u2.arbitrary::<Vec<Action>>().unwrap()
        }
    };

    match gen.random_range(0..=4) {
        0 => {
            // extend
            data1.append(&mut data2);
        }
        1 => {
            // splice at random index
            if data1.is_empty() || data2.is_empty() {
                return 0;
            }
            let idx1 = gen.random_range(0..data1.len());
            let idx2 = gen.random_range(0..data2.len());
            let idx = std::cmp::min(idx1, idx2);
            data1[..idx].copy_from_slice(&data2[..idx]);
        }
        2 => {
            // insert at random index
            if data1.is_empty() || data2.is_empty() {
                return 0;
            }
            let idx = gen.random_range(0..data1.len());
            let action = data2.pop().unwrap();
            data1.insert(idx, action);
        }
        3 => {
            // interleave
            let mut i = 0;
            let mut j = 0;
            let mut new_data = Vec::new();
            while i < data1.len() && j < data2.len() {
                if gen.random_bool(0.5) {
                    new_data.push(data1[i]);
                    i += 1;
                } else {
                    new_data.push(data2[j]);
                    j += 1;
                }
            }
            data1 = new_data;
        }
        4 => {
            data1.reverse();
        }
        _ => {}
    }

    let compressed = bincode::serialize(&data1).unwrap();

    let new_size = std::cmp::min(out.len(), compressed.len());

    out[..new_size].copy_from_slice(&compressed[..new_size]);

    new_size as usize
});

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    let mut gen = StdRng::seed_from_u64(seed.into());

    let mut data1: Vec<Action> = match bincode::deserialize(data) {
        Ok(data) => data,
        Err(_) => {
            let mut u1 = Unstructured::new(data);
            u1.arbitrary::<Vec<Action>>().unwrap()
        }
    };
    // `high` must not equal `low` for `random_range(low..high)`
    if data1.is_empty() {
        fuzzer_mutate(data, size, max_size);
        return size;
    }
    match gen.random_range(0..=3) {
        0 => {
            data1.remove(gen.random_range(0..data1.len()));
        }

        1 => {
            data1.repeat(gen.random_range(0..30));
        }

        2 => {
            // low values
            let idx = gen.random_range(0..data1.len());
            data1[idx] = match gen.random_range(0..=1) {
                0 => Action::F(U256::ZERO),
                1 => Action::G(U256::ZERO),
                _ => unreachable!(),
            };
        }
        3 => {
            // high values
            let idx = gen.random_range(0..data1.len());
            data1[idx] = match gen.random_range(0..=1) {
                0 => Action::F(U256::MAX),
                1 => Action::G(U256::MAX),
                _ => unreachable!(),
            };
        }
        4 => {
            // add or subtract
            let idx = gen.random_range(0..data1.len());
            let add = gen.random_bool(0.5);
            data1[idx] = match data1[idx] {
                Action::F(x) => {
                    if add {
                        Action::F(x.wrapping_add(U256::from(gen.random_range(0..=100))))
                    } else {
                        Action::F(x.wrapping_sub(U256::from(gen.random_range(0..=100))))
                    }
                }
                Action::G(x) => {
                    if add {
                        Action::G(x.wrapping_add(U256::from(gen.random_range(0..=100))))
                    } else {
                        Action::G(x.wrapping_sub(U256::from(gen.random_range(0..=100))))
                    }
                }
                _ => unreachable!(),
            };
        }

        _ => {}
    }

    let compressed = bincode::serialize(&data1).unwrap();

    let new_size = std::cmp::min(max_size, compressed.len());
    data[..new_size].copy_from_slice(&compressed[..new_size]);
    new_size
});
