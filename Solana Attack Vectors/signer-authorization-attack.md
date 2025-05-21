# Signer Authorization Attack

## Introduction

In Solana, marking an account as a `Signer` ensures that the private key signed the transaction, but it does **not** automatically validate whether the signer is **authorized** to act on a specific account. If a program relies solely on the `Signer` constraint without verifying that the signer matches a stored authority, an attacker can exploit this to perform unauthorized actions, such as modifying sensitive state.

---

## Attack Scenario: Missing Authority Validation

The following implementation allows **any signer** to modify the escrow data without validating their authority:

```rust
pub fn insecure_authorization(ctx: Context<InsecureAuthorization>, data: u8) -> Result<()> {
    let escrow = &mut ctx.accounts.escrow;
    escrow.data = data;
    ...
}

#[derive(Accounts)]
pub struct InsecureAuthorization<'info> {
    pub authority: Signer<'info>,
    /// CHECK: This is not correct
    #[account(
        mut,
        seeds = [b"escrow".as_ref()],
        bump
    )]
    pub escrow: Account<'info, Escrow>,
}

#[account]
pub struct Escrow {
    pub authority: Pubkey,
    pub data: u8,
}
```

In this case, although `authority` is a signer, the program does not check if it matches `escrow.authority`. This allows **any wallet** to sign and update `escrow.data` as long as they pass in a valid signer and the correct PDA.

---

## Mitigation: Enforce Explicit Authority Checks

To prevent this, ensure the signer’s address matches the authority stored in the account by using either program logic or Anchor constraints.

### Manual Check

```rust
pub fn secure_authorization(ctx: Context<SecureAuthorization>, data: u8) -> Result<()> {
    let escrow = &mut ctx.accounts.escrow;

    if escrow.authority != ctx.accounts.authority.key() {
        return Err(ErrorCode::Unauthorized.into());
    }

    escrow.data = data;
    ...
}
```

### Anchor Constraint

```rust
#[derive(Accounts)]
pub struct SecureAuthorization<'info> {
    pub authority: Signer<'info>,
    #[account(
        mut,
        seeds = [b"escrow".as_ref()],
        bump,
        has_one = authority
    )]
    pub escrow: Account<'info, Escrow>,
}
```

This ensures that **only the correct authority** associated with the `Escrow` account can execute the instruction, even if multiple signers are involved in the transaction.

---

## Conclusion

Assuming a signer is authorized without validating their link to the on-chain state introduces critical authorization flaws. **Always** verify signer identity against stored authority fields, either through explicit checks or `has_one` constraints, to ensure only trusted parties can modify protected data.
