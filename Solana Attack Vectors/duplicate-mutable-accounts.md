# Duplicate Mutable Accounts in Solana Programs

## Introduction
When a Solana instruction processes multiple mutable accounts of the same type, an attacker can pass the same account multiple times, leading to unintended state modifications. This vulnerability allows bypassing expected logic, manipulating balances, or causing incorrect state updates.

## Attack Scenario: Using the Same Account Twice
The following implementation does not prevent duplicate accounts from being passed:

```rust
pub fn insecure_atomic_trade(ctx: Context<AtomicTrade>, transfer_amount: u64) -> Result<()> {
    ...
    let fee = transfer_amount
        .checked_mul(FEE_BPS)
        .unwrap()
        .checked_div(BPS)
        .unwrap();

    let fee_deducted = transfer_amount.checked_sub(fee).unwrap();

    fee_vault.amount = fee_vault.amount.checked_add(fee).unwrap();
    vault_a.amount = vault_a.amount.checked_add(fee_deducted).unwrap();
    vault_b.amount = vault_b.amount.checked_sub(fee_deducted).unwrap();
    ...
}
```

If the attacker sets `vault_a` and `vault_b` to the same account, the program will add and subtract from the same balance, potentially leading to incorrect deductions, infinite balance increases, or logic inconsistencies.

## Mitigation: Ensuring Unique Account Inputs
To prevent this attack, enforce a check ensuring distinct accounts:

```rust
pub fn secure_atomic_trade(ctx: Context<AtomicTrade>, transfer_amount: u64) -> Result<()> {
    ...
    if vault_a.key() == vault_b.key() {
        return err!(AtomicTradeError::DuplicateVaults);
    }

    let fee = transfer_amount
        .checked_mul(FEE_BPS)
        .unwrap()
        .checked_div(BPS)
        .unwrap();
    ...
}
```

Alternatively, you can use Anchor constraints:

```rust
#[account(
    ...
    constraint = vault_a.key() != vault_b.key() @ AtomicTradeError::DuplicateVaults,
    ...
)]
pub vault_a: Account<'info, Vault>
```

This ensures that an instruction cannot be executed with the same account passed twice.

## Conclusion
Allowing duplicate mutable accounts without validation can lead to balance manipulation, unintended logic execution, and potential exploits. Always enforce uniqueness checks using explicit conditions or Anchor constraints to maintain transaction integrity.
