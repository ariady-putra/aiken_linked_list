use aiken/collection/dict.{has_key}
use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use aiken/interval.{Interval}
use aiken/primitive/bytearray
use cardano/assets.{AssetName, PolicyId, Value, to_dict, tokens}
use cardano/transaction.{InlineDatum, Input, Output, Transaction}
use linkedlist/constants
use linkedlist/types.{Common, Empty, Key, NodePair, POSIXTime, SetNode}

pub fn validate_mint(
  mints: Value,
  expected_minting_policy: ByteArray,
  expected_minting_name: ByteArray,
  expected_minting_amt: Int,
) -> Bool {
  let mints_policy =
    mints |> assets.tokens(expected_minting_policy) |> dict.to_pairs
  mints_policy == [Pair(expected_minting_name, expected_minting_amt)]
}

pub fn cover_key(node: SetNode, insert_key: VerificationKeyHash) -> Bool {
  let less_than_key =
    when node.key is {
      Key(key) -> bytearray.compare(key, insert_key) == Less
      Empty -> True
    }
  let more_than_key =
    when node.next is {
      Key(key) -> bytearray.compare(key, insert_key) == Greater
      Empty -> True
    }

  and {
    less_than_key?,
    more_than_key?,
  }
}

pub fn as_predecessor_of(
  node: SetNode,
  next_key: VerificationKeyHash,
) -> SetNode {
  SetNode { key: node.key, next: Key(next_key) }
}

pub fn as_successor_of(prev_key: VerificationKeyHash, node: SetNode) -> SetNode {
  SetNode { key: Key(prev_key), next: node.next }
}

pub fn div_ceil(a, b: Int) -> Int {
  let div = a / b
  let rem = a % b

  when rem is {
    0 -> div
    _ -> div + 1
  }
}

pub fn make_common(
  Transaction { inputs, outputs, mint, validity_range, extra_signatories, .. },
  own_cs: PolicyId,
) -> (
  Common,
  List<Input>,
  List<Output>,
  List<VerificationKeyHash>,
  Interval<POSIXTime>,
) {
  let in_outputs = get_outputs(inputs)

  let from_node_val = in_outputs |> only_at_node_val(own_cs)
  let to_node_val = outputs |> only_at_node_val(own_cs)

  // Something like: SELECT COUNT DISTINCT address MUST BE 1 FROM (from_node_val UNION to_node_val)
  expect [_] =
    {
      let Output { address, .. } <-
        list.map(from_node_val |> list.concat(to_node_val))
      address
    }
      |> list.unique

  let node_inputs = from_node_val |> list.map(node_input_utxo_datum_unsafe)
  let node_outputs = {
    let node <- list.map(to_node_val)
    parse_node_output_utxo(own_cs, node)
  }

  let common = Common { own_cs, mint, node_inputs, node_outputs }
  (common, inputs, outputs, extra_signatories, validity_range)
}

// Checks if a Currency Symbol is held within a Value
pub fn has_data_cs(value: Value, cs: PolicyId) -> Bool {
  value |> to_dict() |> has_key(cs)
}

pub fn get_outputs(inputs: List<Input>) -> List<Output> {
  let Input { output, .. } <- list.map(inputs)
  output
}

pub fn only_at_node_val(outputs: List<Output>, cs: PolicyId) -> List<Output> {
  let Output { value, .. } <- list.filter(outputs)
  value |> has_data_cs(cs)
}

pub fn node_input_utxo_datum_unsafe(output: Output) -> NodePair {
  expect Output { value, datum: InlineDatum(raw_node), .. } = output
  expect node: SetNode = raw_node

  NodePair { val: value, node }
}

pub fn parse_node_output_utxo(cs: PolicyId, output: Output) -> NodePair {
  expect Output { value, datum: InlineDatum(raw_node), .. } = output
  expect node: SetNode = raw_node

  expect [Pair(tn, 1)] = value |> tokens(cs) |> dict.to_pairs

  let node_key = parse_node_key(tn)
  let datum_key =
    when node.key is {
      Key(key) -> Some(key)
      Empty -> None
    }

  expect node_key == datum_key
  expect list.length(value |> assets.flatten) == 2

  expect valid_node(node)
  expect find_cs_by_token_prefix(value, constants.set_node_prefix) == [cs]

  NodePair { val: value, node }
}

pub fn parse_node_key(tn: AssetName) -> Option<ByteArray> {
  let prefix_length = constants.set_node_prefix |> bytearray.length
  let tn_length = tn |> bytearray.length
  let key = tn |> bytearray.drop(prefix_length)

  expect constants.set_node_prefix == bytearray.take(tn, prefix_length)

  if prefix_length < tn_length {
    Some(key)
  } else {
    None
  }
}

pub fn valid_node(node: SetNode) -> Bool {
  when node is {
    SetNode(Empty, _) | SetNode(_, Empty) -> True
    SetNode(Key(node_key), Key(next_key)) ->
      bytearray.compare(node_key, next_key) == Less
  }
}

pub fn find_cs_by_token_prefix(
  value: Value,
  prefix: ByteArray,
) -> List<PolicyId> {
  let (cs, tn, _amt) <- list.filter_map(value |> assets.flatten)
  if is_prefix_of(prefix, tn) {
    Some(cs)
  } else {
    None
  }
}

pub fn is_prefix_of(prefix: ByteArray, src: ByteArray) -> Bool {
  let prefix_length = prefix |> bytearray.length
  let src_length = src |> bytearray.length

  if prefix_length <= src_length {
    bytearray.take(src, prefix_length) == prefix
  } else {
    False
  }
}
