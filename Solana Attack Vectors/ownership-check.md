# Ownership Check: Securing Token Accounts in Solana

## Introduction

Failing to verify account ownership allows an attacker to substitute arbitrary accounts, leading to unauthorized actions.  
If a program does not confirm that a token account belongs to the expected owner and is associated with the correct mint, an attacker can inject a malicious token account to manipulate balances or gain access to funds they do not own.

---

## Attack Scenario: Missing Ownership and Mint Verification

The following insecure implementation does **not** enforce ownership validation, allowing an attacker to pass in arbitrary token accounts:

```rust
pub fn insecure_log_balance_v1(ctx: Context<InsecureOwnershipv1>) -> Result<()> {
    msg!(
        "The balance: {} of Token Account: {} corresponds to owner: {} and Mint: {}",
        ctx.accounts.token_account.amount,
        ctx.accounts.token_account.key(),
        ctx.accounts.token_account_owner.key(),
        ctx.accounts.mint.key(),
    );
    Ok(())
}

#[derive(Accounts)]
pub struct InsecureOwnershipv1<'info> {
    pub mint: Account<'info, Mint>,
    pub token_account: Account<'info, TokenAccount>,
    pub token_account_owner: Signer<'info>,
}
```

**Problem:**  
Since `token_account` ownership and mint association are not validated, an attacker can supply any token account — potentially gaining access to funds or manipulating balances.

---

## Mitigation: Enforcing Ownership and Mint Verification

To prevent unauthorized token account usage, enforce strict ownership and mint constraints:

```rust
#[derive(Accounts)]
pub struct SecureOwnershipv1<'info> {
    pub mint: Account<'info, Mint>,
    #[account(
        token::authority = token_account_owner,
        token::mint = mint
    )]
    pub token_account: Account<'info, TokenAccount>,
    pub token_account_owner: Signer<'info>,
}
```

This ensures that:
- `token_account` is **owned** by `token_account_owner`, preventing unauthorized access.
- `token_account` is **associated** with the provided `mint`, blocking injection of arbitrary accounts.

---

## Conclusion

Without verifying token ownership and mint association, attackers can pass in malicious token accounts, enabling unauthorized transactions and fund access.

**Always enforce explicit constraints on token accounts** to ensure only legitimate owners and mint associations are allowed. This simple check could save your protocol from catastrophic vulnerabilities.
