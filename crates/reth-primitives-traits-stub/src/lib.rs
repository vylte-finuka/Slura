use alloy_primitives::{B256, U256};

#[derive(Clone, Copy, Debug, Default)]
pub struct Account {
    pub nonce: u64,
    pub balance: U256,
    pub bytecode_hash: Option<B256>,
}
