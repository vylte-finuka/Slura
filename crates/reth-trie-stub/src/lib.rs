//! Stub minimal de reth-trie (compilation locale sans pull git reth).
use alloy_primitives::{B256, U256};

#[derive(Clone, Copy, Debug, Default)]
pub struct TrieAccount {
    pub nonce: u64,
    pub balance: U256,
    pub storage_root: B256,
    pub code_hash: B256,
}

pub mod root {
    use super::*;

    pub fn state_root<I>(_accounts: I) -> B256
    where
        I: IntoIterator<Item = (B256, TrieAccount)>,
    {
        B256::ZERO
    }
}

#[derive(Clone, Debug, Default)]
pub struct HashedPostState {
    accounts: Vec<(B256, Option<()>)>,
}

impl HashedPostState {
    pub fn with_accounts<I, A>(mut self, accounts: I) -> Self
    where
        I: IntoIterator<Item = (B256, Option<A>)>,
    {
        // On ignore le type de compte ; seul le nombre d'entrées compte pour le stub.
        self.accounts = accounts.into_iter().map(|(k, v)| (k, v.map(|_| ()))).collect();
        self
    }
}
