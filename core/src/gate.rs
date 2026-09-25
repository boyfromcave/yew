//! The broadcast gate (D-W-5): every `confirm` passes through here and there is no override.
//! Refuses any transaction that spends a TOKEN, PENDING_TOKEN, VAULT or CARRIER input on the
//! YEC path, or whose YED payload does not round-trip through `payload`. Phase W1 (YEC), W2 (YED).
