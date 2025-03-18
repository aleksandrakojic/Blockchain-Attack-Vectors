# Solana Account Revival Attacks

## Introduction
Solana programs rely on external accounts to store state, unlike Ethereum’s internal contract storage. When closing an account, the Solana runtime garbage collects it only if the account’s balance is reduced to zero and it is no longer rent-exempt. However, if an attacker can prevent an account from being garbage collected after a program marks it as closed, they can revive it and use it in unintended ways.

This vulnerability, known as a **revival attack**, occurs when an account is improperly closed, allowing an attacker to keep using it for unauthorized transactions, drain protocol funds, or exploit re-initialization bugs.

---

## Understanding Solana Accounts
### Closing an Account Improperly Opens an Opportunity for Revival Attacks
The Solana runtime garbage collects accounts when they are no longer rent-exempt. Closing accounts involves transferring the lamports stored in the account for rent exemption to another account of your choosing.

You can use the Anchor `#[account(close = <address_to_send_lamports>)]` constraint to securely close accounts and set the account discriminator to the `CLOSED_ACCOUNT_DISCRIMINATOR`:

```rust
#[account(mut, close = receiver)]
pub data_account: Account<'info, MyData>,
#[account(mut)]
pub receiver: SystemAccount<'info>
```

While it sounds simple, closing accounts properly can be tricky. There are a number of ways an attacker could circumvent having the account closed if you don't follow specific steps.

---

## Attack Scenario: Insecure Account Closing
In Solana, closing an account involves transferring its lamports to another account, which triggers the runtime garbage collection process. Once this happens, the ownership of the closed account is reset from the owning program back to the system program.

### Example of an Insecure Closure Process
The following example demonstrates an insecure account closure process. The instruction requires two accounts:
- `account_to_close` – The account intended for closure.
- `destination` – The recipient of the lamports from the closed account.

The program logic is designed to close an account by simply increasing the destination account's lamports by the amount stored in `account_to_close` and setting `account_to_close` lamports to `0`. With this program, after a full transaction is processed, `account_to_close` will be garbage collected by the runtime.

```rust
pub fn close(ctx: Context<Close>) -> ProgramResult {
    let dest_starting_lamports = ctx.accounts.destination.lamports();

    **ctx.accounts.destination.lamports.borrow_mut() = dest_starting_lamports
       .checked_add(ctx.accounts.account_to_close.to_account_info().lamports())
       .unwrap();
    **ctx.accounts.account_to_close.to_account_info().lamports.borrow_mut() = 0;
    Ok(())
}
```

### How Attackers Exploit This
Garbage collection does not take place until the transaction is fully executed. Since a transaction can contain multiple instructions, an attacker can exploit this delay by including an instruction to close the account while simultaneously adding another instruction to refund its rent-exemption lamports before the transaction completes. 

This prevents the account from being garbage collected, allowing the attacker to reuse the account for unintended actions, potentially leading to exploits such as reward manipulation or protocol fund drainage.

---

## Mitigation Strategies: Secure Account Closing
### Use the Anchor `close` Constraint
Fortunately, Anchor makes secure account closure simpler with the `#[account(close = <target_account>)]` constraint. This constraint handles everything required to securely close an account:

- Transfers the account's lamports to the given `<target_account>`
- Zeroes out the account data
- Sets the account discriminator to the `CLOSED_ACCOUNT_DISCRIMINATOR` variant

All you have to do is add it in the account validation struct to the account you want closed:

```rust
#[derive(Accounts)]
pub struct CloseAccount {
    #[account(
        mut,
        close = receiver
    )]
    pub data_account: Account<'info, MyData>,
    #[account(mut)]
    pub receiver: SystemAccount<'info>
}
```

---

## Conclusion
Improperly closing Solana accounts creates serious **revival attack** risks, allowing attackers to reuse accounts for unauthorized actions, such as draining rewards, manipulating state, or even causing denial-of-service attacks. 

By implementing secure account closure techniques—such as using Anchor’s close constraint (preferable), zeroing out account data, enforcing closed account discriminators, or implementing a force defund function—developers can ensure that accounts are truly closed and cannot be revived for malicious purposes.
