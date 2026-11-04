//! Transparent account state, coinbase maturity, allowances, and canonical serialization.
//!
//! Defined in `docs/protocol-v1.md` §7.3 and ADR-004.

use crate::hash::Hash;

/// The initial scheduled block subsidy in atoms (10 OWN).
pub const STARTING_SUBSIDY_ATOMS: u128 = 1_000_000_000;

/// The number of blocks between subsidy halvings (1,050,000 blocks).
pub const HALVING_INTERVAL_BLOCKS: u64 = 1_050_000;

/// The absolute maximum supply cap in atoms (21,000,000 OWN).
pub const MAX_SUPPLY_ATOMS: u128 = 2_100_000_000_000_000;

/// Coinbase maturity duration in blocks (100 blocks).
pub const COINBASE_MATURITY_BLOCKS: u64 = 100;

/// Default delay for transfers to unconfirmed recipients (10 blocks).
pub const DEFAULT_NEW_RECIPIENT_DELAY: u32 = 10;

/// Default delay for cross-pool withdrawals (144 blocks).
pub const DEFAULT_WITHDRAWAL_DELAY: u32 = 144;

/// Domain separator for address derivation.
pub const DOMAIN_ADDRESS: &[u8] = b"OwnChain/Address/v1";

/// Derives a transparent account address from an Ed25519 public key.
///
/// `address = BLAKE2b-256("OwnChain/Address/v1" || ed25519_pubkey[32])`.
pub fn derive_address(ed25519_pubkey: &[u8; 32]) -> Hash {
    crate::hash::hash_domained(DOMAIN_ADDRESS, ed25519_pubkey)
}

/// Computes scheduled block subsidy in atoms for `height`.
///
/// Genesis (height 0) has subsidy 0.
/// Heights 1..=1,050,000 have 10 OWN (1,000,000,000 atoms).
/// Subsidy halves every 1,050,000 blocks until Era 30+ (exhaustion).
pub fn scheduled_subsidy(height: u64) -> u128 {
    if height == 0 {
        return 0;
    }
    let era = (height - 1) / HALVING_INTERVAL_BLOCKS;
    if era >= 30 {
        return 0;
    }
    STARTING_SUBSIDY_ATOMS >> era
}

/// A pending outgoing transfer subject to time-lock delay.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PendingTransfer {
    /// Unique transfer ID (`BLAKE2b-256(tx_id || "/pending")`).
    pub transfer_id: Hash,
    /// Destination address.
    pub recipient: Hash,
    /// Transfer principal in atoms.
    pub amount: u128,
    /// Block height at which transfer is released.
    pub release_height: u64,
}

impl PendingTransfer {
    /// Serializes pending transfer into canonical 88 bytes matching `protocol-v1.md` §7.3:
    /// `transfer_id[32] || recipient[32] || amount[16] || release_height[8]`.
    pub fn serialize(&self) -> [u8; 88] {
        let mut out = [0u8; 88];
        out[..32].copy_from_slice(self.transfer_id.as_bytes());
        out[32..64].copy_from_slice(self.recipient.as_bytes());
        out[64..80].copy_from_slice(&self.amount.to_le_bytes());
        out[80..88].copy_from_slice(&self.release_height.to_le_bytes());
        out
    }
}

/// An immature coinbase payout tranche subject to 100-block maturity.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CoinbaseTranche {
    /// Coinbase transaction ID.
    pub coinbase_tx_id: Hash,
    /// Payout amount in atoms.
    pub amount: u128,
    /// Block height at which tranche matures (`height + 100`).
    pub unlock_height: u64,
}

impl CoinbaseTranche {
    /// Serializes coinbase tranche into canonical 56 bytes.
    pub fn serialize(&self) -> [u8; 56] {
        let mut out = [0u8; 56];
        out[..32].copy_from_slice(self.coinbase_tx_id.as_bytes());
        out[32..48].copy_from_slice(&self.amount.to_le_bytes());
        out[48..56].copy_from_slice(&self.unlock_height.to_le_bytes());
        out
    }
}

/// Errors occurring during spendable balance calculation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SpendableBalanceError {
    /// Spendable balance calculation resulted in underflow.
    NegativeSpendableBalance,
}

impl core::fmt::Display for SpendableBalanceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SpendableBalanceError::NegativeSpendableBalance => {
                write!(f, "negative spendable balance calculation")
            }
        }
    }
}

impl std::error::Error for SpendableBalanceError {}

/// Transparent account state on the ledger.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccountState {
    /// Total balance (mature + immature coinbase + pending outgoing).
    pub balance: u128,
    /// Strictly sequential account nonce.
    pub nonce: u64,
    /// Maximum spending allowance per window (0 = disabled/unlimited).
    pub allowance_limit: u128,
    /// Starting block height of current allowance window.
    pub allowance_window_start: u64,
    /// Length of allowance window in blocks.
    pub allowance_window_len: u64,
    /// Amount spent in current allowance window.
    pub allowance_spent: u128,
    /// Whether the account is currently frozen by guardians.
    pub is_frozen: bool,
    /// Recovery Ed25519 public key (32 bytes).
    pub recovery_key: [u8; 32],
    /// Whether guardian protections are active.
    pub guardian_enabled: bool,
    /// Delay for transfers to new/unconfirmed recipients.
    pub new_recipient_delay: u32,
    /// Delay for cross-pool withdrawals.
    pub withdrawal_delay: u32,
    /// 7 registered guardian Ed25519 public keys.
    pub guardians: [[u8; 32]; 7],
    /// Outgoing transfers pending time-lock release.
    pub pending_transfers: Vec<PendingTransfer>,
    /// Coinbase tranches awaiting maturity.
    pub coinbase_tranches: Vec<CoinbaseTranche>,
}

impl Default for AccountState {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountState {
    /// Creates a new default account state.
    pub fn new() -> Self {
        Self {
            balance: 0,
            nonce: 0,
            allowance_limit: 0,
            allowance_window_start: 0,
            allowance_window_len: 0,
            allowance_spent: 0,
            is_frozen: false,
            recovery_key: [0u8; 32],
            guardian_enabled: false,
            new_recipient_delay: DEFAULT_NEW_RECIPIENT_DELAY,
            withdrawal_delay: DEFAULT_WITHDRAWAL_DELAY,
            guardians: [[0u8; 32]; 7],
            pending_transfers: Vec::new(),
            coinbase_tranches: Vec::new(),
        }
    }

    /// Sum of coinbase tranches where `unlock_height > height`.
    pub fn immature_coinbase_balance(&self, height: u64) -> u128 {
        self.coinbase_tranches
            .iter()
            .filter(|t| t.unlock_height > height)
            .map(|t| t.amount)
            .sum()
    }

    /// Sum of pending outgoing transfer amounts.
    pub fn pending_outgoing_balance(&self) -> u128 {
        self.pending_transfers.iter().map(|p| p.amount).sum()
    }

    /// Mature spendable balance = `balance - immature_coinbase - pending_outgoing`.
    pub fn spendable_balance(&self, height: u64) -> Result<u128, SpendableBalanceError> {
        let immature = self.immature_coinbase_balance(height);
        let pending = self.pending_outgoing_balance();
        let encumbered = immature
            .checked_add(pending)
            .ok_or(SpendableBalanceError::NegativeSpendableBalance)?;
        self.balance
            .checked_sub(encumbered)
            .ok_or(SpendableBalanceError::NegativeSpendableBalance)
    }

    /// Canonical account serialization matching `protocol-v1.md` §7.3.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(342);

        // 0..16: balance u128_le
        out.extend_from_slice(&self.balance.to_le_bytes());
        // 16..24: nonce u64_le
        out.extend_from_slice(&self.nonce.to_le_bytes());
        // 24..40: allowance_limit u128_le
        out.extend_from_slice(&self.allowance_limit.to_le_bytes());
        // 40..48: allowance_window_start u64_le
        out.extend_from_slice(&self.allowance_window_start.to_le_bytes());
        // 48..56: allowance_window_len u64_le
        out.extend_from_slice(&self.allowance_window_len.to_le_bytes());
        // 56..72: allowance_spent u128_le
        out.extend_from_slice(&self.allowance_spent.to_le_bytes());
        // 72..73: is_frozen u8
        out.push(if self.is_frozen { 1 } else { 0 });
        // 73..105: recovery_key [u8; 32]
        out.extend_from_slice(&self.recovery_key);
        // 105..106: guardian_enabled u8
        out.push(if self.guardian_enabled { 1 } else { 0 });
        // 106..110: new_recipient_delay u32_le
        out.extend_from_slice(&self.new_recipient_delay.to_le_bytes());
        // 110..114: withdrawal_delay u32_le
        out.extend_from_slice(&self.withdrawal_delay.to_le_bytes());
        // 114..338: guardians [u8; 224] (7 * 32)
        for g in &self.guardians {
            out.extend_from_slice(g);
        }

        // 338..342: pending_transfers_count u32_le
        let mut sorted_pending = self.pending_transfers.clone();
        sorted_pending.sort_by_key(|p| p.transfer_id);
        out.extend_from_slice(&(sorted_pending.len() as u32).to_le_bytes());
        for p in &sorted_pending {
            out.extend_from_slice(&p.serialize());
        }

        // coinbase_tranches_count u32_le
        let mut sorted_tranches = self.coinbase_tranches.clone();
        sorted_tranches.sort_by_key(|t| (t.unlock_height, t.coinbase_tx_id));
        out.extend_from_slice(&(sorted_tranches.len() as u32).to_le_bytes());
        for t in &sorted_tranches {
            out.extend_from_slice(&t.serialize());
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduled_subsidy_schedule() {
        // Genesis height 0 has zero subsidy
        assert_eq!(scheduled_subsidy(0), 0);

        // Era 0: 10 OWN (1,000,000,000 atoms)
        assert_eq!(scheduled_subsidy(1), 1_000_000_000);
        assert_eq!(scheduled_subsidy(1_049_999), 1_000_000_000); // Immediately before 1st halving
        assert_eq!(scheduled_subsidy(1_050_000), 1_000_000_000); // At 1st halving boundary

        // Era 1: 5 OWN (500,000,000 atoms)
        assert_eq!(scheduled_subsidy(1_050_001), 500_000_000); // Immediately after 1st halving
        assert_eq!(scheduled_subsidy(2_099_999), 500_000_000); // Immediately before 2nd halving
        assert_eq!(scheduled_subsidy(2_100_000), 500_000_000); // At 2nd halving boundary

        // Era 2: 2.5 OWN (250,000,000 atoms)
        assert_eq!(scheduled_subsidy(2_100_001), 250_000_000); // Immediately after 2nd halving

        // Exhaustion boundary at Era 30 (height 31,500,001)
        assert_eq!(scheduled_subsidy(31_499_999), 1); // Era 29 penultimate block
        assert_eq!(scheduled_subsidy(31_500_000), 1); // Era 29 last block (1 atom)
        assert_eq!(scheduled_subsidy(31_500_001), 0); // Era 30 first block: exhausted!
        assert_eq!(scheduled_subsidy(100_000_000), 0);
    }

    #[test]
    fn test_spendable_balance() {
        let mut acc = AccountState::new();
        acc.balance = 1_000_000_000;
        acc.coinbase_tranches.push(CoinbaseTranche {
            coinbase_tx_id: Hash::ZERO,
            amount: 600_000_000,
            unlock_height: 101,
        });
        acc.pending_transfers.push(PendingTransfer {
            transfer_id: Hash::ZERO,
            recipient: Hash::ZERO,
            amount: 100_000_000,
            release_height: 11,
        });

        // At height 100: coinbase is immature (600M), pending is 100M -> spendable = 300M
        assert_eq!(acc.spendable_balance(100).unwrap(), 300_000_000);
        // At height 101: coinbase matures -> spendable = 900M
        assert_eq!(acc.spendable_balance(101).unwrap(), 900_000_000);
    }

    #[test]
    fn test_pending_transfer_canonical_serialization_88_bytes() {
        let transfer_id = Hash::new([0x11; 32]);
        let recipient = Hash::new([0x22; 32]);
        let amount = 0x0102030405060708090a0b0c0d0e0f10u128;
        let release_height = 0xa1a2a3a4a5a6a7a8u64;

        let pending = PendingTransfer {
            transfer_id,
            recipient,
            amount,
            release_height,
        };

        let bytes = pending.serialize();
        assert_eq!(bytes.len(), 88);

        // Verify non-overlapping layout and field recovery
        assert_eq!(&bytes[..32], transfer_id.as_bytes());
        assert_eq!(&bytes[32..64], recipient.as_bytes());
        assert_eq!(
            u128::from_le_bytes(bytes[64..80].try_into().unwrap()),
            amount
        );
        assert_eq!(
            u64::from_le_bytes(bytes[80..88].try_into().unwrap()),
            release_height
        );
    }

    #[test]
    fn test_empty_account_state_canonical_size_346_bytes() {
        let acc = AccountState::new();
        let bytes = acc.serialize();
        assert_eq!(bytes.len(), 346);
    }
}
