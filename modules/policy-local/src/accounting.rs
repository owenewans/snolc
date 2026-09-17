use thiserror::Error;

pub struct QuotaAccount {
    limit_bytes: Option<u64>,
    durable_charged: u64,
    credit_remaining: u64,
    block_bytes: u64,
    debit_pending: bool,
    refund_pending: bool,
}

impl QuotaAccount {
    pub fn new(
        limit_bytes: Option<u64>,
        durable_charged: u64,
        block_bytes: u64,
    ) -> Result<Self, QuotaError> {
        if block_bytes == 0 || limit_bytes.is_some_and(|limit| durable_charged > limit) {
            return Err(QuotaError::Invalid);
        }
        Ok(Self {
            limit_bytes,
            durable_charged,
            credit_remaining: 0,
            block_bytes,
            debit_pending: false,
            refund_pending: false,
        })
    }

    pub fn request_credit(&mut self) -> Result<u64, QuotaError> {
        if self.credit_remaining != 0 || self.debit_pending || self.refund_pending {
            return Err(QuotaError::State);
        }
        let available = self
            .limit_bytes
            .map(|limit| limit.saturating_sub(self.durable_charged))
            .unwrap_or(self.block_bytes);
        let amount = available.min(self.block_bytes);
        if amount == 0 {
            return Err(QuotaError::Exhausted);
        }
        self.debit_pending = true;
        Ok(amount)
    }

    pub fn commit_credit(&mut self, amount: u64) -> Result<(), QuotaError> {
        if !self.debit_pending || amount == 0 || amount > self.block_bytes {
            return Err(QuotaError::State);
        }
        let next = self
            .durable_charged
            .checked_add(amount)
            .ok_or(QuotaError::Overflow)?;
        if self.limit_bytes.is_some_and(|limit| next > limit) {
            return Err(QuotaError::Exhausted);
        }
        self.durable_charged = next;
        self.credit_remaining = amount;
        self.debit_pending = false;
        Ok(())
    }

    pub fn fail_credit(&mut self) {
        self.debit_pending = false;
        self.credit_remaining = 0;
    }

    pub fn charge(&mut self, accepted_bytes: u64) -> Result<(), QuotaError> {
        if accepted_bytes > self.credit_remaining {
            return Err(QuotaError::Exhausted);
        }
        self.credit_remaining -= accepted_bytes;
        Ok(())
    }

    pub fn checkpoint_refund(&mut self) -> Result<u64, QuotaError> {
        let refund = self.request_refund()?;
        self.commit_refund(refund)?;
        Ok(refund)
    }

    pub fn request_refund(&mut self) -> Result<u64, QuotaError> {
        if self.debit_pending || self.refund_pending {
            return Err(QuotaError::State);
        }
        let refund = self.credit_remaining;
        if refund == 0 {
            return Err(QuotaError::State);
        }
        self.refund_pending = true;
        Ok(refund)
    }

    pub fn commit_refund(&mut self, refund: u64) -> Result<(), QuotaError> {
        if !self.refund_pending || refund == 0 || refund != self.credit_remaining {
            return Err(QuotaError::State);
        }
        self.durable_charged = self
            .durable_charged
            .checked_sub(refund)
            .ok_or(QuotaError::State)?;
        self.credit_remaining = 0;
        self.refund_pending = false;
        Ok(())
    }

    pub fn fail_refund(&mut self) {
        self.refund_pending = false;
        self.credit_remaining = 0;
    }

    pub fn durable_charged(&self) -> u64 {
        self.durable_charged
    }

    pub fn credit_remaining(&self) -> u64 {
        self.credit_remaining
    }
}

pub struct TokenBucket {
    rate_bytes_per_second: u64,
    burst_bytes: u64,
    tokens: u64,
    last_nanos: u64,
    fractional: u64,
}

impl TokenBucket {
    pub fn new(
        rate_bytes_per_second: u64,
        burst_bytes: u64,
        now_nanos: u64,
    ) -> Result<Self, QuotaError> {
        if rate_bytes_per_second == 0 || burst_bytes == 0 {
            return Err(QuotaError::Invalid);
        }
        Ok(Self {
            rate_bytes_per_second,
            burst_bytes,
            tokens: burst_bytes,
            last_nanos: now_nanos,
            fractional: 0,
        })
    }

    pub fn take(&mut self, requested: u64, now_nanos: u64) -> Result<u64, QuotaError> {
        self.refill(now_nanos)?;
        let granted = requested.min(self.tokens);
        self.tokens -= granted;
        Ok(granted)
    }

    pub fn nanos_until(&mut self, bytes: u64, now_nanos: u64) -> Result<u64, QuotaError> {
        self.refill(now_nanos)?;
        if self.tokens >= bytes {
            return Ok(0);
        }
        let missing = bytes - self.tokens;
        let numerator = missing
            .checked_mul(1_000_000_000)
            .ok_or(QuotaError::Overflow)?;
        Ok(numerator
            .checked_add(self.rate_bytes_per_second - 1)
            .ok_or(QuotaError::Overflow)?
            / self.rate_bytes_per_second)
    }

    pub fn refund(&mut self, bytes: u64) {
        self.tokens = self.tokens.saturating_add(bytes).min(self.burst_bytes);
    }

    fn refill(&mut self, now_nanos: u64) -> Result<(), QuotaError> {
        if now_nanos < self.last_nanos {
            return Err(QuotaError::Clock);
        }
        let elapsed = now_nanos - self.last_nanos;
        let produced = elapsed
            .checked_mul(self.rate_bytes_per_second)
            .and_then(|value| value.checked_add(self.fractional))
            .ok_or(QuotaError::Overflow)?;
        let added = produced / 1_000_000_000;
        self.fractional = produced % 1_000_000_000;
        self.tokens = self.tokens.saturating_add(added).min(self.burst_bytes);
        self.last_nanos = now_nanos;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum QuotaError {
    #[error("accounting configuration is invalid")]
    Invalid,
    #[error("accounting state transition is invalid")]
    State,
    #[error("quota is exhausted")]
    Exhausted,
    #[error("accounting arithmetic overflow")]
    Overflow,
    #[error("monotonic clock moved backwards")]
    Clock,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_credit_is_shared_by_all_flows() {
        let mut account = QuotaAccount::new(Some(2_000_000), 0, 1_048_576).unwrap();
        let debit = account.request_credit().unwrap();
        account.commit_credit(debit).unwrap();
        account.charge(400_000).unwrap();
        account.charge(500_000).unwrap();
        assert_eq!(account.credit_remaining(), 148_576);
        assert!(matches!(account.request_credit(), Err(QuotaError::State)));
    }

    #[test]
    fn checkpoint_refunds_but_crash_state_stays_debited() {
        let mut account = QuotaAccount::new(Some(5_000_000), 0, 1_048_576).unwrap();
        let debit = account.request_credit().unwrap();
        account.commit_credit(debit).unwrap();
        account.charge(48_576).unwrap();
        assert_eq!(account.durable_charged(), 1_048_576);
        assert_eq!(account.checkpoint_refund().unwrap(), 1_000_000);
        assert_eq!(account.durable_charged(), 48_576);
    }

    #[test]
    fn refund_changes_state_only_after_commit() {
        let mut account = QuotaAccount::new(Some(2_000_000), 0, 1_048_576).unwrap();
        let debit = account.request_credit().unwrap();
        account.commit_credit(debit).unwrap();
        account.charge(48_576).unwrap();
        let refund = account.request_refund().unwrap();
        assert_eq!(account.durable_charged(), 1_048_576);
        assert_eq!(account.credit_remaining(), 1_000_000);
        account.commit_refund(refund).unwrap();
        assert_eq!(account.durable_charged(), 48_576);
        assert_eq!(account.credit_remaining(), 0);
    }

    #[test]
    fn integer_token_bucket_refills_without_float() {
        let mut bucket = TokenBucket::new(1_000, 2_000, 0).unwrap();
        assert_eq!(bucket.take(2_000, 0).unwrap(), 2_000);
        assert_eq!(bucket.take(1_000, 500_000_000).unwrap(), 500);
        assert_eq!(bucket.nanos_until(500, 500_000_000).unwrap(), 500_000_000);
        bucket.refund(250);
        assert_eq!(bucket.take(500, 500_000_000).unwrap(), 250);
    }
}
