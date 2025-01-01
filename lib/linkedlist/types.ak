use aiken/crypto.{VerificationKeyHash}
use cardano/address.{Address}
use cardano/assets.{AssetName, PolicyId, Value}
use cardano/transaction.{OutputReference}

/// A number of milliseconds since 00:00:00 UTC on 1 January 1970.
pub type POSIXTime =
  Int

pub type AssetClass {
  policy_id: PolicyId,
  asset_name: AssetName,
}

pub type Config {
  init_utxo: OutputReference,
  deadline: POSIXTime,
  penalty_address: Address,
}

pub type NodeKey {
  Key { key: VerificationKeyHash }
  Empty
}

pub type SetNode {
  key: NodeKey,
  next: NodeKey,
}

pub type NodePair {
  val: Value,
  node: SetNode,
}

pub type Common {
  own_cs: PolicyId,
  mint: Value,
  node_inputs: List<NodePair>,
  node_outputs: List<NodePair>,
}

pub type NodeAction {
  Init
  Deinit
  Insert {
    key_to_insert: VerificationKeyHash,
    /// | Covering node **INPUT**, ie. the datum **before** transaction |
    /// |---------------------------------------------------------------|
    /// | <img src="https://raw.githubusercontent.com/ariady-putra/aiken_linked_list/refs/heads/main/assets/images/covering-node-insert.png"/> |
    covering_node: SetNode,
  }
  Remove {
    key_to_remove: VerificationKeyHash,
    /// | Covering node **OUTPUT**, ie. the datum **after** transaction |
    /// |---------------------------------------------------------------|
    /// | <img src="https://raw.githubusercontent.com/ariady-putra/aiken_linked_list/refs/heads/main/assets/images/covering-node-remove.png"/> |
    covering_node: SetNode,
  }
}
