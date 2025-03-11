# Arbitrary CPI Attacks in Solana

## Introduction
Solana programs frequently rely on **Cross-Program Invocations (CPIs)** to execute logic from other on-chain programs. If a program does not verify that it is calling the correct target program, attackers can pass a malicious program ID instead, hijacking execution and performing unintended operations. This oversight gives an attacker full control over the CPI’s behavior, allowing them to manipulate accounts, bypass security checks, or execute unauthorized transactions.

This attack occurs when a program **accepts an externally supplied program ID without validation** and invokes it blindly. The attacker can inject a custom program that behaves maliciously while appearing to follow expected logic.

## Understanding Arbitrary CPI Attacks
Solana CPIs allow a program to interact with another program by specifying a **target program ID** and required accounts. The problem arises when a program blindly trusts an external program ID and invokes it without confirming its authenticity. If an attacker supplies their own program instead of the expected one, they can redirect execution and implement custom logic that compromises the system.

Verifying the program ID before performing a CPI ensures that only the intended logic executes. If this check is missing, the attacker gains complete control over how the CPI behaves, allowing them to introduce security risks.

## Attack Scenario: Calling an Arbitrary Program Without Validation

```rust
pub fn insecure_verify_pin(
    ctx: Context<InsecureVerifyPinCPI>,
    ...
) -> Result<()> {
    let cpi_program = ctx.accounts.secret_program.to_account_info();

    let cpi_accounts = VerifyPin {
        author: ctx.accounts.author.to_account_info(),
        secret_information: ctx.accounts.secret_information.to_account_info(),
    };
    let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);

    arbitrary_cpi_expected::cpi::verify_pin(cpi_ctx, pin1, pin2, pin3, pin4)?;
    ...
}
```

### Breakdown of the vulnerability:
- `ctx.accounts.secret_program` is **taken as input without verification**.
- Since the **program ID is not checked**, an attacker can substitute their own malicious program.
- The CPI call will execute logic from the attacker’s program, potentially manipulating data or bypassing security checks.
- The **Solana runtime does not enforce which program gets called in a CPI**, so explicit verification is required to prevent unauthorized execution.

## Mitigation Strategies: Ensuring Program ID Validation
To prevent arbitrary CPI attacks, **always verify that the program being called is the expected program before making the CPI**. The correct approach is to explicitly check the program ID before execution.

### Secure Implementation:

```rust
pub fn secure_verify_pin(
    ctx: Context<SecureVerifyPinCPI>,
    ...
) -> Result<()> {
    let cpi_program = ctx.accounts.secret_program.to_account_info();

    if cpi_program.key() != arbitrary_cpi_expected::ID {
        return err!(ArbitraryCPIError::CPIProgramIDMismatch);
    }

    let cpi_accounts = VerifyPin {
        author: ctx.accounts.author.to_account_info(),
        secret_information: ctx.accounts.secret_information.to_account_info(),
    };
    let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);

    arbitrary_cpi_expected::cpi::verify_pin(cpi_ctx, pin1, pin2, pin3, pin4)?;
    ...
}
```

### Key Improvements:
- Before making the CPI, the program **checks if `ctx.accounts.secret_program` matches the expected `arbitrary_cpi_expected::ID`**.
- If the check fails, the **transaction is aborted**, preventing any unintended execution.
- This approach eliminates the risk of an attacker injecting a **malicious program** into the CPI call.

## Conclusion
Blindly accepting an externally supplied program ID in a Solana CPI is a **serious security risk**. If an attacker substitutes a malicious program, they can manipulate execution flow, override expected logic, and gain unauthorized control over protocol operations.

By **verifying the program ID before executing a CPI**, developers can ensure that only the correct logic runs, effectively mitigating this class of attack.

