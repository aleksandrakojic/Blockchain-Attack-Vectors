# Bump Seed Canonicalization Attack

## Introduction

Solana PDAs are derived using a set of seeds and a bump seed. If a program uses `create_program_address` with a user-supplied bump **without enforcing canonicality**, it can result in **multiple valid PDAs for the same seed inputs**. This undermines the uniqueness of PDAs and opens up potential attack surfaces where a user can create multiple valid accounts for the same logical identity, leading to inconsistent state and unauthorized actions.

---

## Attack Scenario: Arbitrary Bump with Non-Canonical Derivation

```rust
pub fn set_value(ctx: Context<BumpSeed>, key: u64, new_value: u64, bump: u8) -> Result<()> {
    let address = Pubkey::create_program_address(
        &[key.to_le_bytes().as_ref(), &[bump]],
        ctx.program_id
    )?;

    if address != ctx.accounts.data.key() {
        return Err(ProgramError::InvalidArgument.into());
    }

    ctx.accounts.data.value = new_value;
    Ok(())
}

#[derive(Accounts)]
pub struct BumpSeed<'info> {
    #[account(mut)]
    pub data: Account<'info, Data>,
}

#[account]
pub struct Data {
    pub value: u64,
}
```

In this implementation, the bump is passed from the user. While the PDA is validated, there is **no enforcement of the canonical bump**. A malicious user can generate and initialize multiple accounts with different valid bumps, breaking the intended one-to-one mapping of seeds to accounts.

---

## Mitigation: Enforce Canonical Bump via `find_program_address`

```rust
pub fn set_value_secure(ctx: Context<BumpSeed>, key: u64, new_value: u64, bump: u8) -> Result<()> {
    let (expected_address, expected_bump) = Pubkey::find_program_address(
        &[key.to_le_bytes().as_ref()],
        ctx.program_id
    );

    if ctx.accounts.data.key() != expected_address || bump != expected_bump {
        return Err(ProgramError::InvalidArgument.into());
    }

    ctx.accounts.data.value = new_value;
    Ok(())
}
```

This ensures that only the PDA using the **canonical bump** is valid. To optimize for future calls, the bump should be stored inside the PDA’s account data during initialization and reused in subsequent validations.

---

## Conclusion

Allowing arbitrary bumps in PDA derivations **weakens the assumption of uniqueness** in seed-based addressing. Always derive PDAs using `find_program_address` to enforce canonicality, and validate bump correctness explicitly or via Anchor constraints to avoid unauthorized account creation.
