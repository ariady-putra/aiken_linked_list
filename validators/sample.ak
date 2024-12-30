use aiken/cbor
use aiken/collection/list
use aiken/crypto
use aiken/fuzz
use aiken/interval
use aiken/primitive/bytearray
use cardano/assets.{PolicyId}
use cardano/transaction.{InlineDatum, Transaction}
use fuzz_util/fuzzer.{
  FromKey, FromScript, Specified, WithFuzzedDelegation, address_fuzzer,
  blake2b_224_fuzzer, output_reference_fuzzer, script_hash_fuzzer,
}
use linkedlist/constants
use linkedlist/linked_list.{deinit, init, insert, remove}
use linkedlist/types.{
  Config, Deinit, Empty, Init, Insert, Key, NodeAction, Remove, SetNode,
}
use linkedlist/utils
use tx_util/builder/txn.{
  add_asset_to_tx_output, add_mint, add_signatory, add_tx_input, add_tx_output,
  set_datum_of_tx_input, set_datum_of_tx_output, set_id, set_validity_range,
  with_asset_of_tx_input,
}
use tx_util/mock.{mock_script_hash, mock_verification_key_hash}

validator mint_validator(cfg: Config) {
  mint(redeemer: NodeAction, policy_id: PolicyId, tx: Transaction) {
    let (common, inputs, outputs, sigs, vrange) =
      tx |> utils.make_common(policy_id)

    when redeemer is {
      Init -> {
        expect {
          let transaction.Input(output_reference, _) <- list.any(inputs)
          output_reference == cfg.init_utxo
        }
        init(common)
      }

      Deinit -> deinit(common)

      Insert(key_to_insert, covering_node_input) -> {
        expect vrange |> interval.is_entirely_before(cfg.deadline)
        expect {
          let sig <- list.any(sigs)
          sig == key_to_insert
        }
        insert(common, key_to_insert, covering_node_input)
      }

      Remove(key_to_remove, covering_node_output) -> {
        expect vrange |> interval.is_entirely_before(cfg.deadline)
        remove(
          common,
          vrange,
          cfg,
          outputs,
          sigs,
          key_to_remove,
          covering_node_output,
        )
      }
    }
  }

  else(_) {
    fail
  }
}

test mint_validator_init(
  (
    own_cs,
    init_output_ref,
    now,
    penalty_address,
    user_address,
    contract_address,
  ) via fuzzer.tuple6(
    script_hash_fuzzer(),
    output_reference_fuzzer(),
    fuzz.int_at_least(1000),
    address_fuzzer(
      FromScript(Specified(mock_script_hash("P"))),
      WithFuzzedDelegation,
    ),
    address_fuzzer(
      FromKey(Specified(mock_verification_key_hash("C"))),
      WithFuzzedDelegation,
    ),
    address_fuzzer(
      FromScript(Specified(mock_script_hash("B"))),
      WithFuzzedDelegation,
    ),
  ),
) {
  let config =
    Config { init_utxo: init_output_ref, deadline: now * 4, penalty_address }

  let datum = SetNode { key: Empty, next: Empty }
  let redeemer = Init

  let minted_value =
    own_cs |> assets.from_asset(constants.origin_node_token_name, 1)

  let init_input =
    txn.new_tx_input(init_output_ref, user_address)
      |> with_asset_of_tx_input(4_000_000 |> assets.from_lovelace)

  let head_output =
    txn.new_tx_output(contract_address)
      |> set_datum_of_tx_output(datum |> InlineDatum)
      |> add_asset_to_tx_output(4_000_000 |> assets.from_lovelace)
      |> add_asset_to_tx_output(minted_value)

  let tx =
    transaction.placeholder
      |> add_tx_input(init_input)
      |> add_tx_output(head_output)
      |> add_mint(minted_value)
  let tx_hash = tx |> cbor.serialise |> crypto.blake2b_256

  config |> mint_validator.mint(redeemer, own_cs, tx |> set_id(tx_hash))
}

test mint_validator_deinit(
  (own_cs, init_output_ref, now, penalty_address, contract_address) via fuzzer.tuple5(
    script_hash_fuzzer(),
    output_reference_fuzzer(),
    fuzz.int_at_least(1000),
    address_fuzzer(
      FromScript(Specified(mock_script_hash("P"))),
      WithFuzzedDelegation,
    ),
    address_fuzzer(
      FromScript(Specified(mock_script_hash("B"))),
      WithFuzzedDelegation,
    ),
  ),
) {
  let config =
    Config { init_utxo: init_output_ref, deadline: now * 4, penalty_address }

  let datum = SetNode { key: Empty, next: Empty }
  let redeemer = Deinit

  let own_cs_value =
    own_cs |> assets.from_asset(constants.origin_node_token_name, 1)
  let burn_value = own_cs_value |> assets.negate

  let head_input =
    txn.new_tx_input(init_output_ref, contract_address)
      |> set_datum_of_tx_input(datum |> InlineDatum)
      |> with_asset_of_tx_input(4_000_000 |> assets.from_lovelace)
      |> with_asset_of_tx_input(own_cs_value)

  let tx =
    transaction.placeholder
      |> add_tx_input(head_input)
      |> add_mint(burn_value)
  let tx_hash = tx |> cbor.serialise |> crypto.blake2b_256

  config |> mint_validator.mint(redeemer, own_cs, tx |> set_id(tx_hash))
}

test mint_validator_deinit_fails_on_non_empty(
  (blake2b_224s, o_refs, now, penalty_address, contract_address) via fuzzer.tuple5(
    blake2b_224_fuzzer(count: 2),
    fuzz.set_between(output_reference_fuzzer(), 2, 2),
    fuzz.int_at_least(1000),
    address_fuzzer(
      FromScript(Specified(mock_script_hash("P"))),
      WithFuzzedDelegation,
    ),
    address_fuzzer(
      FromScript(Specified(mock_script_hash("I"))),
      WithFuzzedDelegation,
    ),
  ),
) fail {
  expect [own_cs, user_pkh] = blake2b_224s
  let user_tn = constants.set_node_prefix |> bytearray.concat(user_pkh)

  expect [init_output_ref, remove_output_ref] = o_refs
  let config =
    Config { init_utxo: init_output_ref, deadline: now * 4, penalty_address }

  let remove_node =
    SetNode { key: Key { key: user_pkh }, next: Key { key: user_pkh } }

  let user_value = own_cs |> assets.from_asset(user_tn, 1)

  let remove_node_output =
    txn.new_tx_input(remove_output_ref, contract_address)
      |> set_datum_of_tx_input(remove_node |> InlineDatum)
      |> with_asset_of_tx_input(9_000_000 |> assets.from_lovelace)
      |> with_asset_of_tx_input(user_value)

  let burn_value =
    own_cs |> assets.from_asset(constants.origin_node_token_name, -1)

  let redeemer = Deinit

  let tx =
    transaction.placeholder
      |> add_tx_input(remove_node_output)
      |> add_mint(burn_value)
  let tx_hash = tx |> cbor.serialise |> crypto.blake2b_256

  config |> mint_validator.mint(redeemer, own_cs, tx |> set_id(tx_hash))
}

test mint_validator_insert(
  (blake2b_224s, o_refs, now, penalty_address, contract_address) via fuzzer.tuple5(
    blake2b_224_fuzzer(count: 3),
    fuzz.set_between(output_reference_fuzzer(), 2, 2),
    fuzz.int_at_least(1000),
    address_fuzzer(
      FromScript(Specified(mock_script_hash("P"))),
      WithFuzzedDelegation,
    ),
    address_fuzzer(
      FromScript(Specified(mock_script_hash("I"))),
      WithFuzzedDelegation,
    ),
  ),
) {
  expect [own_cs, ..tail] = blake2b_224s
  expect [user1_pkh, user2_pkh] = tail |> list.sort(bytearray.compare)
  let covering_tn = constants.set_node_prefix |> bytearray.concat(user1_pkh)
  let insert_tn = constants.set_node_prefix |> bytearray.concat(user2_pkh)

  expect [init_output_ref, covering_output_ref] = o_refs
  let config =
    Config { init_utxo: init_output_ref, deadline: now * 4, penalty_address }

  let covering_minted_value = own_cs |> assets.from_asset(covering_tn, 1)

  let covering_node_value =
    assets.from_lovelace(9_000_000) |> assets.merge(covering_minted_value)

  let covering_node = SetNode { key: Key { key: user1_pkh }, next: Empty }

  let covering_output =
    txn.new_tx_input(covering_output_ref, contract_address)
      |> set_datum_of_tx_input(covering_node |> InlineDatum)
      |> with_asset_of_tx_input(covering_node_value)

  let out_prev_node = SetNode { ..covering_node, next: Key { key: user2_pkh } }

  let out_prev_node_output =
    txn.new_tx_output(contract_address)
      |> set_datum_of_tx_output(out_prev_node |> InlineDatum)
      |> add_asset_to_tx_output(covering_node_value)

  let out_node = SetNode { key: Key { key: user2_pkh }, next: Empty }

  let insert_minted_value = own_cs |> assets.from_asset(insert_tn, 1)

  let out_node_output =
    txn.new_tx_output(contract_address)
      |> set_datum_of_tx_output(out_node |> InlineDatum)
      |> add_asset_to_tx_output(9_000_000 |> assets.from_lovelace)
      |> add_asset_to_tx_output(insert_minted_value)

  let redeemer = Insert { key_to_insert: user2_pkh, covering_node }

  let insert_timerange = interval.entirely_between(now, now * 2)

  let tx =
    transaction.placeholder
      |> set_validity_range(insert_timerange)
      |> add_tx_input(covering_output)
      |> add_tx_output(out_prev_node_output)
      |> add_tx_output(out_node_output)
      |> add_mint(insert_minted_value)
      |> add_signatory(user2_pkh)
  let tx_hash = tx |> cbor.serialise |> crypto.blake2b_256

  config |> mint_validator.mint(redeemer, own_cs, tx |> set_id(tx_hash))
}

test mint_validator_remove(
  (blake2b_224s, o_refs, now, penalty_address, contract_address) via fuzzer.tuple5(
    blake2b_224_fuzzer(count: 3),
    fuzz.set_between(output_reference_fuzzer(), 3, 3),
    fuzz.int_at_least(1000),
    address_fuzzer(
      FromScript(Specified(mock_script_hash("P"))),
      WithFuzzedDelegation,
    ),
    address_fuzzer(
      FromScript(Specified(mock_script_hash("I"))),
      WithFuzzedDelegation,
    ),
  ),
) {
  expect [own_cs, ..tail] = blake2b_224s
  expect [user1_pkh, user2_pkh] = tail |> list.sort(bytearray.compare)
  let covering_tn = constants.set_node_prefix |> bytearray.concat(user1_pkh)
  let user2_tn = constants.set_node_prefix |> bytearray.concat(user2_pkh)

  expect [init_output_ref, covering_output_ref, remove_output_ref] = o_refs
  let config =
    Config { init_utxo: init_output_ref, deadline: now * 4, penalty_address }

  let covering_minted_value = own_cs |> assets.from_asset(covering_tn, 1)

  let covering_node_value =
    assets.from_lovelace(9_000_000) |> assets.merge(covering_minted_value)

  let covering_node =
    SetNode { key: Key { key: user1_pkh }, next: Key { key: user2_pkh } }

  let covering_output =
    txn.new_tx_input(covering_output_ref, contract_address)
      |> set_datum_of_tx_input(covering_node |> InlineDatum)
      |> with_asset_of_tx_input(covering_node_value)

  let remove_node = SetNode { key: Key { key: user2_pkh }, next: Empty }

  let user2_value = assets.from_asset(own_cs, user2_tn, 1)

  let remove_node_output =
    txn.new_tx_input(remove_output_ref, contract_address)
      |> set_datum_of_tx_input(remove_node |> InlineDatum)
      |> with_asset_of_tx_input(9_000_000 |> assets.from_lovelace)
      |> with_asset_of_tx_input(user2_value)

  let output_node = SetNode { ..covering_node, next: Empty }

  let out_node_output =
    txn.new_tx_output(contract_address)
      |> set_datum_of_tx_output(output_node |> InlineDatum)
      |> add_asset_to_tx_output(covering_node_value)

  let remove_burn_value = own_cs |> assets.from_asset(user2_tn, -1)

  let redeemer = Remove { key_to_remove: user2_pkh, covering_node: output_node }

  let remove_timerange = interval.entirely_between(now, now * 2)

  let tx =
    transaction.placeholder
      |> set_validity_range(remove_timerange)
      |> add_tx_input(remove_node_output)
      |> add_tx_input(covering_output)
      |> add_tx_output(out_node_output)
      |> add_mint(remove_burn_value)
      |> add_signatory(user2_pkh)
  let tx_hash = tx |> cbor.serialise |> crypto.blake2b_256

  config |> mint_validator.mint(redeemer, own_cs, tx |> set_id(tx_hash))
}
