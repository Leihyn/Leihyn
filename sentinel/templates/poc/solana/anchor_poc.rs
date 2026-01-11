// Solana/Anchor Exploit PoC Template
// Common attack vectors for Solana programs

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("ExamplePoCProgramId11111111111111111111111");

/// ============================================================================
/// COMMON SOLANA VULNERABILITIES
/// ============================================================================
///
/// 1. Missing Signer Check - Most critical
/// 2. Account Confusion / Type Cosplay
/// 3. PDA Seed Manipulation
/// 4. Missing Owner Check
/// 5. Integer Overflow/Underflow
/// 6. Reinitialization Attack
/// 7. Closing Account Incorrectly
/// 8. Arbitrary CPI (Cross-Program Invocation)

#[program]
pub mod exploit_poc {
    use super::*;

    // =========================================================================
    // VULNERABILITY 1: Missing Signer Check
    // =========================================================================
    // VULNERABLE: No signer validation on authority
    pub fn vulnerable_withdraw(ctx: Context<VulnerableWithdraw>, amount: u64) -> Result<()> {
        // BUG: authority is not checked as signer!
        // Anyone can pass any pubkey as authority
        let vault = &ctx.accounts.vault;

        // Attacker can drain by passing vault.authority as authority account
        // without actually signing
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.vault_token.to_account_info(),
                    to: ctx.accounts.user_token.to_account_info(),
                    authority: ctx.accounts.vault.to_account_info(),
                },
            ),
            amount,
        )?;
        Ok(())
    }

    // SAFE: Proper signer check
    pub fn safe_withdraw(ctx: Context<SafeWithdraw>, amount: u64) -> Result<()> {
        // authority is marked as Signer in account struct
        let vault = &ctx.accounts.vault;
        let seeds = &[b"vault", vault.authority.as_ref(), &[vault.bump]];
        let signer = &[&seeds[..]];

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.vault_token.to_account_info(),
                    to: ctx.accounts.user_token.to_account_info(),
                    authority: ctx.accounts.vault.to_account_info(),
                },
                signer,
            ),
            amount,
        )?;
        Ok(())
    }

    // =========================================================================
    // VULNERABILITY 2: Account Confusion / Type Cosplay
    // =========================================================================
    // VULNERABLE: Using AccountInfo without type validation
    pub fn vulnerable_process<'info>(
        ctx: Context<'_, '_, '_, 'info, VulnerableProcess<'info>>,
    ) -> Result<()> {
        // BUG: data_account is raw AccountInfo
        // Attacker can pass ANY account, including one they control
        let data = &ctx.accounts.data_account;

        // Deserializing without checking discriminator!
        let parsed: UserData = UserData::try_from_slice(&data.data.borrow())?;

        // Attacker controls parsed.amount, can set to any value
        msg!("Processing amount: {}", parsed.amount);
        Ok(())
    }

    // SAFE: Using Account<T> with proper deserialization
    pub fn safe_process(ctx: Context<SafeProcess>) -> Result<()> {
        // Anchor's Account<T> validates:
        // 1. Discriminator matches UserData
        // 2. Owner is this program
        let data = &ctx.accounts.data_account;
        msg!("Processing amount: {}", data.amount);
        Ok(())
    }

    // =========================================================================
    // VULNERABILITY 3: PDA Seed Manipulation
    // =========================================================================
    // VULNERABLE: User-controlled seed without validation
    pub fn vulnerable_create_account(
        ctx: Context<VulnerableCreate>,
        seed: String,  // BUG: Attacker controls this!
    ) -> Result<()> {
        // Attacker can create accounts that collide with other users
        // by manipulating the seed
        let account = &mut ctx.accounts.user_account;
        account.owner = ctx.accounts.payer.key();
        account.data = seed;
        Ok(())
    }

    // SAFE: Seeds tied to user's pubkey
    pub fn safe_create_account(ctx: Context<SafeCreate>) -> Result<()> {
        // Seed includes user's pubkey - no collision possible
        let account = &mut ctx.accounts.user_account;
        account.owner = ctx.accounts.payer.key();
        Ok(())
    }

    // =========================================================================
    // VULNERABILITY 4: Missing Owner Check
    // =========================================================================
    // VULNERABLE: Not checking account owner
    pub fn vulnerable_read<'info>(
        ctx: Context<'_, '_, '_, 'info, VulnerableRead<'info>>,
    ) -> Result<()> {
        let account_info = &ctx.accounts.target_account;

        // BUG: Not checking if this program owns the account!
        // Attacker can pass account owned by different program
        // with malicious data layout
        let data: &[u8] = &account_info.data.borrow();

        // Parse and trust the data...
        Ok(())
    }

    // SAFE: Owner check
    pub fn safe_read(ctx: Context<SafeRead>) -> Result<()> {
        // Anchor's Account<T> checks owner automatically
        let account = &ctx.accounts.target_account;
        // Safe to use account.data
        Ok(())
    }

    // =========================================================================
    // VULNERABILITY 5: Integer Overflow
    // =========================================================================
    // VULNERABLE: Unchecked arithmetic
    pub fn vulnerable_math(ctx: Context<MathContext>, amount: u64) -> Result<()> {
        let account = &mut ctx.accounts.counter;

        // BUG: Can overflow! In release mode, wraps around
        account.value = account.value + amount;

        Ok(())
    }

    // SAFE: Checked arithmetic
    pub fn safe_math(ctx: Context<MathContext>, amount: u64) -> Result<()> {
        let account = &mut ctx.accounts.counter;

        // checked_add returns Option, errors on overflow
        account.value = account.value
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;

        Ok(())
    }

    // =========================================================================
    // VULNERABILITY 6: Reinitialization
    // =========================================================================
    // VULNERABLE: Can reinitialize already-initialized account
    pub fn vulnerable_init(ctx: Context<VulnerableInit>) -> Result<()> {
        let account = &mut ctx.accounts.data;

        // BUG: No check if already initialized!
        // Attacker can reset account state
        account.authority = ctx.accounts.payer.key();
        account.balance = 0;

        Ok(())
    }

    // SAFE: Check initialization flag
    pub fn safe_init(ctx: Context<SafeInit>) -> Result<()> {
        let account = &mut ctx.accounts.data;

        // Anchor's init constraint handles this
        // Or manually: require!(!account.is_initialized, AlreadyInitialized);
        account.is_initialized = true;
        account.authority = ctx.accounts.payer.key();
        account.balance = 0;

        Ok(())
    }

    // =========================================================================
    // VULNERABILITY 7: Closing Account Incorrectly
    // =========================================================================
    // VULNERABLE: Not zeroing account data on close
    pub fn vulnerable_close(ctx: Context<VulnerableClose>) -> Result<()> {
        let account = &ctx.accounts.data;
        let dest = &ctx.accounts.destination;

        // Transfer lamports
        **dest.to_account_info().try_borrow_mut_lamports()? +=
            **account.to_account_info().lamports.borrow();
        **account.to_account_info().try_borrow_mut_lamports()? = 0;

        // BUG: Data not zeroed!
        // Account can be "revived" in same transaction
        // with original data still present

        Ok(())
    }

    // SAFE: Use Anchor's close constraint or zero data
    pub fn safe_close(ctx: Context<SafeClose>) -> Result<()> {
        // Anchor's close constraint handles everything:
        // 1. Zero data
        // 2. Transfer lamports
        // 3. Set discriminator to CLOSED
        Ok(())
    }
}

// ============================================================================
// ACCOUNT STRUCTURES
// ============================================================================

#[derive(Accounts)]
pub struct VulnerableWithdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    /// CHECK: BUG - not marked as Signer!
    pub authority: AccountInfo<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct SafeWithdraw<'info> {
    #[account(
        mut,
        has_one = authority,  // Validates authority matches
    )]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,  // SAFE: Must sign
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct VulnerableProcess<'info> {
    /// CHECK: BUG - raw AccountInfo, no validation
    pub data_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct SafeProcess<'info> {
    #[account(
        constraint = data_account.owner == payer.key() @ ErrorCode::InvalidOwner
    )]
    pub data_account: Account<'info, UserData>,
    pub payer: Signer<'info>,
}

#[derive(Accounts)]
pub struct VulnerableCreate<'info> {
    #[account(
        init,
        // BUG: seed controlled by user input!
        seeds = [b"user", seed.as_bytes()],
        bump,
        payer = payer,
        space = 8 + 32 + 100
    )]
    pub user_account: Account<'info, UserAccount>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SafeCreate<'info> {
    #[account(
        init,
        // SAFE: seed tied to payer's pubkey
        seeds = [b"user", payer.key().as_ref()],
        bump,
        payer = payer,
        space = 8 + 32 + 100
    )]
    pub user_account: Account<'info, UserAccount>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct VulnerableRead<'info> {
    /// CHECK: BUG - no owner validation
    pub target_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct SafeRead<'info> {
    // Account<T> validates owner is this program
    pub target_account: Account<'info, UserData>,
}

#[derive(Accounts)]
pub struct MathContext<'info> {
    #[account(mut)]
    pub counter: Account<'info, Counter>,
}

#[derive(Accounts)]
pub struct VulnerableInit<'info> {
    #[account(mut)]
    pub data: Account<'info, InitData>,
    #[account(mut)]
    pub payer: Signer<'info>,
}

#[derive(Accounts)]
pub struct SafeInit<'info> {
    #[account(
        init,  // init constraint prevents reinitialization
        payer = payer,
        space = 8 + InitData::INIT_SPACE
    )]
    pub data: Account<'info, InitData>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct VulnerableClose<'info> {
    #[account(mut)]
    pub data: Account<'info, InitData>,
    /// CHECK: destination for lamports
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct SafeClose<'info> {
    #[account(
        mut,
        close = destination,  // Anchor handles closing safely
        has_one = authority,
    )]
    pub data: Account<'info, InitData>,
    pub authority: Signer<'info>,
    /// CHECK: destination for lamports
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub bump: u8,
}

#[account]
pub struct UserData {
    pub owner: Pubkey,
    pub amount: u64,
}

#[account]
pub struct UserAccount {
    pub owner: Pubkey,
    pub data: String,
}

#[account]
pub struct Counter {
    pub value: u64,
}

#[account]
#[derive(InitSpace)]
pub struct InitData {
    pub is_initialized: bool,
    pub authority: Pubkey,
    pub balance: u64,
}

// ============================================================================
// ERRORS
// ============================================================================

#[error_code]
pub enum ErrorCode {
    #[msg("Integer overflow")]
    Overflow,
    #[msg("Invalid account owner")]
    InvalidOwner,
    #[msg("Account already initialized")]
    AlreadyInitialized,
}

// ============================================================================
// TEST TEMPLATE
// ============================================================================
/*
#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::solana_program::system_program;
    use solana_program_test::*;
    use solana_sdk::{
        signature::{Keypair, Signer},
        transaction::Transaction,
    };

    #[tokio::test]
    async fn test_missing_signer_exploit() {
        // Setup test environment
        let program_id = crate::id();
        let mut program_test = ProgramTest::new(
            "exploit_poc",
            program_id,
            processor!(exploit_poc::entry),
        );

        let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

        // Create victim's vault
        let victim = Keypair::new();
        let attacker = Keypair::new();

        // ... setup accounts ...

        // Attacker calls withdraw without being the signer
        // This should succeed if vulnerable, fail if safe
    }
}
*/
