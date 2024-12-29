use aiken/collection/list
use aiken/interval
use aiken/primitive/bytearray
use cardano/address
use cardano/assets.{PolicyId}
use cardano/transaction.{InlineDatum, OutputReference, Transaction}
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

      Insert { key_to_insert, covering_node } -> {
        expect vrange |> interval.is_entirely_before(cfg.deadline)
        expect {
          let sig <- list.any(sigs)
          sig == key_to_insert
        }
        insert(common, key_to_insert, covering_node)
      }

      Remove { key_to_remove, covering_node } -> {
        expect vrange |> interval.is_entirely_before(cfg.deadline)
        remove(common, vrange, cfg, outputs, sigs, key_to_remove, covering_node)
      }
    }
  }

  else(_) {
    fail
  }
}

test mint_validator_init() {
  let own_cs = #"746fa3ba2daded6ab9ccc1e39d3835aa1dfcb9b5a54acc2ebe6b79a4"

  let init_output_ref =
    OutputReference {
      transaction_id: #"2c6dbc95c1e96349c4131a9d19b029362542b31ffd2340ea85dd8f28e271ff6d",
      output_index: 1,
    }

  let config =
    Config {
      init_utxo: init_output_ref,
      deadline: 86_400_000,
      penalty_address: "P" |> address.from_script,
    }

  let datum = SetNode { key: Empty, next: Empty }
  let redeemer = Init

  let minted_value =
    own_cs |> assets.from_asset(constants.origin_node_token_name, 1)

  let init_input =
    txn.new_tx_input(init_output_ref, "C" |> address.from_verification_key)
      |> with_asset_of_tx_input(4_000_000 |> assets.from_lovelace)

  let head_output =
    txn.new_tx_output("B" |> address.from_script)
      |> set_datum_of_tx_output(datum |> InlineDatum)
      |> add_asset_to_tx_output(4_000_000 |> assets.from_lovelace)
      |> add_asset_to_tx_output(minted_value)

  let tx =
    transaction.placeholder
      |> set_id(
          #"2c6dbc95c1e96349c4131a9d19b029362542b31ffd2340ea85dd8f28e271ff6d",
        )
      |> add_tx_input(init_input)
      |> add_tx_output(head_output)
      |> add_mint(minted_value)

  config |> mint_validator.mint(redeemer, own_cs, tx)
}

test mint_validator_deinit() {
  let own_cs = #"746fa3ba2daded6ab9ccc1e39d3835aa1dfcb9b5a54acc2ebe6b79a4"

  let init_output_ref =
    OutputReference {
      transaction_id: #"2c6dbc95c1e96349c4131a9d19b029362542b31ffd2340ea85dd8f28e271ff6d",
      output_index: 1,
    }

  let config =
    Config {
      init_utxo: init_output_ref,
      deadline: 86_400_000,
      penalty_address: "P" |> address.from_script,
    }

  let datum = SetNode { key: Empty, next: Empty }
  let redeemer = Deinit

  let own_cs_value =
    own_cs |> assets.from_asset(constants.origin_node_token_name, 1)
  let burn_value =
    own_cs |> assets.from_asset(constants.origin_node_token_name, -1)

  let head_input =
    txn.new_tx_input(init_output_ref, "B" |> address.from_script)
      |> set_datum_of_tx_input(datum |> InlineDatum)
      |> with_asset_of_tx_input(4_000_000 |> assets.from_lovelace)
      |> with_asset_of_tx_input(own_cs_value)

  let tx =
    transaction.placeholder
      |> set_id(
          #"2c6dbc95c1e96349c4131a9d19b029362542b31ffd2340ea85dd8f28e271ff6d",
        )
      |> add_tx_input(head_input)
      |> add_mint(burn_value)

  mint_validator.mint(config, redeemer, own_cs, tx)
}

test mint_validator_deinit_fails_on_non_empty() fail {
  let own_cs = #"746fa3ba2daded6ab9ccc1e39d3835aa1dfcb9b5a54acc2ebe6b79a4"

  let init_output_ref =
    OutputReference {
      transaction_id: #"2c6dbc95c1e96349c4131a9d19b029362542b31ffd2340ea85dd8f28e271ff6d",
      output_index: 1,
    }

  let config =
    Config {
      init_utxo: init_output_ref,
      deadline: 86_400_000,
      penalty_address: "P" |> address.from_script,
    }

  let user2_pkh = #"e18d73505be6420225ed2a42c8e975e4c6f9148ab38e951ea2572e54"
  let user2_tn = "FSN" |> bytearray.concat(user2_pkh)

  let remove_output_ref =
    OutputReference { transaction_id: #"", output_index: 1 }

  let remove_node =
    SetNode { key: Key { key: user2_pkh }, next: Key { key: user2_pkh } }

  let user2_value = own_cs |> assets.from_asset(user2_tn, 1)

  let remove_node_output =
    txn.new_tx_input(remove_output_ref, "I" |> address.from_script)
      |> set_datum_of_tx_input(remove_node |> InlineDatum)
      |> with_asset_of_tx_input(9_000_000 |> assets.from_lovelace)
      |> with_asset_of_tx_input(user2_value)

  let burn_value =
    own_cs |> assets.from_asset(constants.origin_node_token_name, -1)

  let redeemer = Deinit

  let tx =
    transaction.placeholder
      |> set_id(
          #"2c6dbc95c1e96349c4131a9d19b029362542b31ffd2340ea85dd8f28e271ff6d",
        )
      |> add_tx_input(remove_node_output)
      |> add_mint(burn_value)

  config |> mint_validator.mint(redeemer, own_cs, tx)
}

test mint_validator_insert() {
  let own_cs = #"746fa3ba2daded6ab9ccc1e39d3835aa1dfcb9b5a54acc2ebe6b79a4"

  let init_output_ref =
    OutputReference {
      transaction_id: #"2c6dbc95c1e96349c4131a9d19b029362542b31ffd2340ea85dd8f28e271ff6d",
      output_index: 1,
    }

  let config =
    Config {
      init_utxo: init_output_ref,
      deadline: 86_400_000,
      penalty_address: "P" |> address.from_script,
    }

  let user1_pkh = #"a65ca58a4e9c755fa830173d2a5caed458ac0c73f97db7faae2e7e3b"
  let covering_tn = "FSN" |> bytearray.concat(user1_pkh)

  let user2_pkh = #"e18d73505be6420225ed2a42c8e975e4c6f9148ab38e951ea2572e54"
  let insert_tn = "FSN" |> bytearray.concat(user2_pkh)

  let covering_minted_value = own_cs |> assets.from_asset(covering_tn, 1)

  let covering_node_value =
    assets.from_lovelace(9_000_000) |> assets.merge(covering_minted_value)

  let covering_node = SetNode { key: Key { key: user1_pkh }, next: Empty }

  let covering_output_ref =
    OutputReference { transaction_id: #"", output_index: 1 }

  let covering_output =
    txn.new_tx_input(covering_output_ref, "I" |> address.from_script)
      |> set_datum_of_tx_input(covering_node |> InlineDatum)
      |> with_asset_of_tx_input(covering_node_value)

  let out_prev_node =
    SetNode { key: covering_node.key, next: Key { key: user2_pkh } }

  let out_prev_node_output =
    txn.new_tx_output("I" |> address.from_script)
      |> set_datum_of_tx_output(out_prev_node |> InlineDatum)
      |> add_asset_to_tx_output(covering_node_value)

  let out_node =
    SetNode { key: Key { key: user2_pkh }, next: covering_node.next }

  let insert_minted_value = own_cs |> assets.from_asset(insert_tn, 1)

  let out_node_output =
    txn.new_tx_output("I" |> address.from_script)
      |> set_datum_of_tx_output(out_node |> InlineDatum)
      |> add_asset_to_tx_output(9_000_000 |> assets.from_lovelace)
      |> add_asset_to_tx_output(insert_minted_value)

  let redeemer = Insert { key_to_insert: user2_pkh, covering_node }

  let insert_timerange = interval.entirely_between(1000, 2000)

  let tx =
    transaction.placeholder
      |> set_id(
          #"2c6dbc95c1e96349c4131a9d19b029362542b31ffd2340ea85dd8f28e271ff6d",
        )
      |> set_validity_range(insert_timerange)
      |> add_tx_input(covering_output)
      |> add_tx_output(out_prev_node_output)
      |> add_tx_output(out_node_output)
      |> add_mint(insert_minted_value)
      |> add_signatory(user2_pkh)

  mint_validator.mint(config, redeemer, own_cs, tx)
}

test mint_validator_remove() {
  let own_cs = #"746fa3ba2daded6ab9ccc1e39d3835aa1dfcb9b5a54acc2ebe6b79a4"

  let init_output_ref =
    OutputReference {
      transaction_id: #"2c6dbc95c1e96349c4131a9d19b029362542b31ffd2340ea85dd8f28e271ff6d",
      output_index: 1,
    }

  let config =
    Config {
      init_utxo: init_output_ref,
      deadline: 86_400_000,
      penalty_address: "P" |> address.from_script,
    }

  let user1_pkh = #"a65ca58a4e9c755fa830173d2a5caed458ac0c73f97db7faae2e7e3b"
  let covering_tn = "FSN" |> bytearray.concat(user1_pkh)

  let user2_pkh = #"e18d73505be6420225ed2a42c8e975e4c6f9148ab38e951ea2572e54"
  let user2_tn = "FSN" |> bytearray.concat(user2_pkh)

  let covering_minted_value = own_cs |> assets.from_asset(covering_tn, 1)

  let covering_node_value =
    assets.from_lovelace(9_000_000) |> assets.merge(covering_minted_value)

  let covering_node =
    SetNode { key: Key { key: user1_pkh }, next: Key { key: user2_pkh } }

  let covering_output_ref =
    OutputReference { transaction_id: #"", output_index: 1 }

  let covering_output =
    txn.new_tx_input(covering_output_ref, "I" |> address.from_script)
      |> set_datum_of_tx_input(covering_node |> InlineDatum)
      |> with_asset_of_tx_input(covering_node_value)

  let remove_output_ref =
    OutputReference { transaction_id: #"", output_index: 1 }

  let remove_node = SetNode { key: Key { key: user2_pkh }, next: Empty }

  let user2_value = assets.from_asset(own_cs, user2_tn, 1)

  let remove_node_output =
    txn.new_tx_input(remove_output_ref, "I" |> address.from_script)
      |> set_datum_of_tx_input(remove_node |> InlineDatum)
      |> with_asset_of_tx_input(9_000_000 |> assets.from_lovelace)
      |> with_asset_of_tx_input(user2_value)

  let output_node = SetNode { key: covering_node.key, next: remove_node.next }

  let out_node_output =
    txn.new_tx_output("I" |> address.from_script)
      |> set_datum_of_tx_output(output_node |> InlineDatum)
      |> add_asset_to_tx_output(covering_node_value)

  let remove_burn_value = own_cs |> assets.from_asset(user2_tn, -1)

  let cover_node = SetNode { key: Key { key: user1_pkh }, next: Empty }

  let redeemer = Remove { key_to_remove: user2_pkh, covering_node: cover_node }

  let remove_timerange = interval.entirely_between(1000, 2000)

  let tx =
    transaction.placeholder
      |> set_id(
          #"2c6dbc95c1e96349c4131a9d19b029362542b31ffd2340ea85dd8f28e271ff6d",
        )
      |> set_validity_range(remove_timerange)
      |> add_tx_input(remove_node_output)
      |> add_tx_input(covering_output)
      |> add_tx_output(out_node_output)
      |> add_mint(remove_burn_value)
      |> add_signatory(user2_pkh)

  config |> mint_validator.mint(redeemer, own_cs, tx)
}
