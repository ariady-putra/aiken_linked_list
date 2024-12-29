use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use aiken/interval.{Interval}
use aiken/primitive/bytearray
use cardano/assets.{lovelace_of}
use cardano/transaction.{Output}
use linkedlist/constants
use linkedlist/types.{Common, Config, Empty, NodePair, POSIXTime, SetNode}
use linkedlist/utils

pub fn init(common: Common) -> Bool {
  let must_spend_nodes =
    fn() { list.length(common.node_inputs) == 0 }

  let must_exactly_one_node_output =
    fn() { list.length(common.node_outputs) == 1 }

  let must_mint_correctly =
    fn() {
      common.mint
        |> utils.validate_mint(common.own_cs, constants.origin_node_token_name, 1)
    }

  and {
    must_spend_nodes()?,
    must_exactly_one_node_output()?,
    must_mint_correctly()?,
  }
}

pub fn deinit(common: Common) -> Bool {
  // expect Empty next from [head]=common.node_inputs
  expect [NodePair { node: SetNode { next: Empty, .. }, .. }] =
    common.node_inputs

  let must_not_produce_node_output =
    fn() { list.length(common.node_outputs) == 0 }

  let must_burn_correctly =
    fn() {
      common.mint
        |> utils.validate_mint(common.own_cs, constants.origin_node_token_name, -1)
    }

  and {
    must_not_produce_node_output()?,
    must_burn_correctly()?,
  }
}

pub fn insert(
  common: Common,
  insert_key: VerificationKeyHash,
  node: SetNode,
) -> Bool {
  let must_cover_inserting_key =
    fn() { node |> utils.cover_key(insert_key) }

  expect [covering_node] = common.node_inputs

  let prev_node_datum = node |> utils.as_predecessor_of(insert_key)
  let node_datum = insert_key |> utils.as_successor_of(node)

  let must_has_datum_in_output =
    fn() {
      let NodePair { node, .. } <- list.any(common.node_outputs)
      node == node_datum
    }

  let must_correct_node_output =
    fn() {
      let NodePair(val, node) <- list.any(common.node_outputs)
      and {
        val == covering_node.val,
        node == prev_node_datum,
      }
    }

  let must_mint_correct =
    fn() {
      common.mint
        |> utils.validate_mint(
            common.own_cs,
            constants.origin_node_token_name |> bytearray.concat(insert_key),
            1,
          )
    }

  and {
    must_cover_inserting_key()?,
    must_has_datum_in_output()?,
    must_correct_node_output()?,
    must_mint_correct()?,
  }
}

pub fn remove(
  common: Common,
  range: Interval<POSIXTime>,
  disc_config: Config,
  outs: List<Output>,
  sigs: List<VerificationKeyHash>,
  remove_key: VerificationKeyHash,
  node: SetNode,
) -> Bool {
  let must_cover_remove_key =
    fn() { node |> utils.cover_key(remove_key) }

  let prev_node_datum = node |> utils.as_predecessor_of(remove_key)
  let node_datum = remove_key |> utils.as_successor_of(node)

  let must_spend_two_nodes =
    fn() { list.length(common.node_inputs) == 2 }

  expect Some(stay_node) = {
    let node_pair <- list.find(common.node_inputs)
    node_pair.node == prev_node_datum
  }

  expect Some(remove_node) = {
    let node_pair <- list.find(common.node_inputs)
    node_pair.node == node_datum
  }

  let remove_token_name =
    constants.origin_node_token_name |> bytearray.concat(remove_key)

  let must_correct_node_output =
    fn() {
      let node_pair <- list.any(common.node_outputs)
      and {
        node_pair.val == stay_node.val,
        node_pair.node == node,
      }
    }

  let must_mint_correct =
    fn() {
      common.mint |> utils.validate_mint(common.own_cs, remove_token_name, -1)
    }

  let must_sign_by_user =
    fn() { sigs |> list.has(remove_key) }

  let own_input_lovelace = lovelace_of(remove_node.val)
  let own_input_fee = own_input_lovelace |> utils.div_ceil(4)
  let disc_deadline = disc_config.deadline

  let must_satisfy_removal_broke_phase_rules =
    fn() {
      if range |> interval.is_entirely_before(disc_deadline) {
        True
      } else {
        let out <- list.any(outs)
        and {
          out.address == disc_config.penalty_address,
          own_input_fee < lovelace_of(out.value),
        }
      }
    }

  and {
    must_cover_remove_key()?,
    must_spend_two_nodes()?,
    must_correct_node_output()?,
    must_mint_correct()?,
    must_sign_by_user()?,
    must_satisfy_removal_broke_phase_rules()?,
  }
}
