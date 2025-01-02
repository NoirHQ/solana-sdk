use crate::{
    feature_set::{libsecp256k1_fail_on_bad_count, libsecp256k1_fail_on_bad_count2, FeatureSet},
    precompiles::PrecompileError,
};

pub const HASHED_PUBKEY_SERIALIZED_SIZE: usize = 20;
pub const SIGNATURE_SERIALIZED_SIZE: usize = 64;
pub const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 11;

/// Offsets of signature data within a secp256k1 instruction.
///
/// See the [module documentation][md] for a complete description.
///
/// [md]: self
#[derive(Default, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct SecpSignatureOffsets {
    /// Offset to 64-byte signature plus 1-byte recovery ID.
    pub signature_offset: u16,
    /// Within the transaction, the index of the instruction whose instruction data contains the signature.
    pub signature_instruction_index: u8,
    /// Offset to 20-byte Ethereum address.
    pub eth_address_offset: u16,
    /// Within the transaction, the index of the instruction whose instruction data contains the address.
    pub eth_address_instruction_index: u8,
    /// Offset to start of message data.
    pub message_data_offset: u16,
    /// Size of message data in bytes.
    pub message_data_size: u16,
    /// Within the transaction, the index of the instruction whose instruction data contains the message.
    pub message_instruction_index: u8,
}

/// Creates an Ethereum address from a secp256k1 public key.
pub fn construct_eth_pubkey(pubkey: &[u8; 64]) -> [u8; HASHED_PUBKEY_SERIALIZED_SIZE] {
    let mut addr = [0u8; HASHED_PUBKEY_SERIALIZED_SIZE];
    addr.copy_from_slice(&sp_io::hashing::keccak_256(&pubkey[..])[12..]);
    assert_eq!(addr.len(), HASHED_PUBKEY_SERIALIZED_SIZE);
    addr
}

/// Verifies the signatures specified in the secp256k1 instruction data.
///
/// This is same the verification routine executed by the runtime's secp256k1 native program,
/// and is primarily of use to the runtime.
///
/// `data` is the secp256k1 program's instruction data. `instruction_datas` is
/// the full slice of instruction datas for all instructions in the transaction,
/// including the secp256k1 program's instruction data.
///
/// `feature_set` is the set of active Solana features. It is used to enable or
/// disable a few minor additional checks that were activated on chain
/// subsequent to the addition of the secp256k1 native program. For many
/// purposes passing `FeatureSet::all_enabled()` is reasonable.
pub fn verify(
    data: &[u8],
    instruction_datas: &[&[u8]],
    feature_set: &FeatureSet,
) -> Result<(), PrecompileError> {
    if data.is_empty() {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    let count = data[0] as usize;
    if (feature_set.is_active(&libsecp256k1_fail_on_bad_count::id())
        || feature_set.is_active(&libsecp256k1_fail_on_bad_count2::id()))
        && count == 0
        && data.len() > 1
    {
        // count is zero but the instruction data indicates that is probably not
        // correct, fail the instruction to catch probable invalid secp256k1
        // instruction construction.
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    let expected_data_size = count
        .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
        .saturating_add(1);
    if data.len() < expected_data_size {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    for i in 0..count {
        let start = i
            .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
            .saturating_add(1);
        let end = start.saturating_add(SIGNATURE_OFFSETS_SERIALIZED_SIZE);

        let offsets: SecpSignatureOffsets = bincode::deserialize(&data[start..end])
            .map_err(|_| PrecompileError::InvalidSignature)?;

        // Parse out signature
        let signature_index = offsets.signature_instruction_index as usize;
        if signature_index >= instruction_datas.len() {
            return Err(PrecompileError::InvalidInstructionDataSize);
        }
        let signature_instruction = instruction_datas[signature_index];
        let sig_start = offsets.signature_offset as usize;
        let sig_end = sig_start.saturating_add(SIGNATURE_SERIALIZED_SIZE);
        if sig_end >= signature_instruction.len() {
            return Err(PrecompileError::InvalidSignature);
        }

        let recovery_id = signature_instruction[sig_end];
        if recovery_id > 3 {
            return Err(PrecompileError::InvalidRecoveryId);
        }

        let mut signature = [0u8; 65];
        signature[..SIGNATURE_SERIALIZED_SIZE]
            .copy_from_slice(&signature_instruction[sig_start..sig_end]);
        signature[SIGNATURE_SERIALIZED_SIZE] = recovery_id;

        // Parse out pubkey
        let eth_address_slice = get_data_slice(
            instruction_datas,
            offsets.eth_address_instruction_index,
            offsets.eth_address_offset,
            HASHED_PUBKEY_SERIALIZED_SIZE,
        )?;

        // Parse out message
        let message_slice = get_data_slice(
            instruction_datas,
            offsets.message_instruction_index,
            offsets.message_data_offset,
            offsets.message_data_size as usize,
        )?;

        let message_hash = sp_io::hashing::keccak_256(message_slice);

        let pubkey = sp_io::crypto::secp256k1_ecdsa_recover(&signature, &message_hash)
            .map_err(|_| PrecompileError::InvalidSignature)?;
        let eth_address = construct_eth_pubkey(&pubkey);

        if eth_address_slice != eth_address {
            return Err(PrecompileError::InvalidSignature);
        }
    }
    Ok(())
}

fn get_data_slice<'a>(
    instruction_datas: &'a [&[u8]],
    instruction_index: u8,
    offset_start: u16,
    size: usize,
) -> Result<&'a [u8], PrecompileError> {
    let signature_index = instruction_index as usize;
    if signature_index >= instruction_datas.len() {
        return Err(PrecompileError::InvalidDataOffsets);
    }
    let signature_instruction = &instruction_datas[signature_index];
    let start = offset_start as usize;
    let end = start.saturating_add(size);
    if end > signature_instruction.len() {
        return Err(PrecompileError::InvalidSignature);
    }

    Ok(&instruction_datas[signature_index][start..end])
}
