# Type Cosplay Attack

## Introduction

In Solana, accounts are deserialized based on their byte size rather than an enforced type system. If two account structures have the same size but different intended uses, an attacker can pass one in place of another. Without explicit type validation, the program may deserialize an unintended account, leading to logic inconsistencies, unauthorized access, or data corruption.

## Attack Scenario: Deserializing an Incorrect Account Type

In this example, User and UserMetadata both occupy 68 bytes, allowing one to be deserialized as the other:

```rust
#[account]
pub struct User {
    pub authority: Pubkey,
    pub metadata_account: Pubkey,
    pub age: u32,
}

#[account]
pub struct UserMetadata {
    pub authority: Pubkey,
    pub user_account: Pubkey,
    pub pin1: u8,
    pub pin2: u8,
    pub pin3: u8,
    pub pin4: u8,
}
```

Since there is no type discriminator, the following function incorrectly deserializes UserMetadata as a User account without validation:

```rust
pub fn insecure_user_read(ctx: Context<InsecureTypeCosplay>) -> Result<()> {
    let user = User::try_from_slice(&ctx.accounts.user.data.borrow())?;
    ...
}

#[derive(Accounts)]
pub struct InsecureTypeCosplay<'info> {
    /// CHECK: unsafe, does not check the Account type
    pub user: AccountInfo<'info>,
    pub authority: Signer<'info>,
}
```

If an attacker passes a UserMetadata account instead of User, the program will incorrectly interpret its fields, leading to unintended logic execution.

## Mitigation: Enforcing Type Validation with Discriminators

To prevent type cosplay, enforce strict type validation using account discriminators and explicit type enforcement:

```rust
pub fn secure_user_read(ctx: Context<SecureTypeCosplay>) -> Result<()> {
    let user = &ctx.accounts.user;
    ...
}

#[derive(Accounts)]
pub struct SecureTypeCosplay<'info> {
    #[account(
        has_one = authority,
    )]
    pub user: Account<'info, User>,
    pub authority: Signer<'info>,
}
```

Anchor automatically prepends a discriminator (an 8-byte identifier) to each account and verifies its type before deserialization, preventing unintended type casting.

## Conclusion

Deserializing accounts without enforcing type validation introduces type confusion vulnerabilities, allowing attackers to bypass logic checks by passing structurally similar accounts. Always use account discriminators and Anchor’s type validation to ensure only the correct account type is processed.
