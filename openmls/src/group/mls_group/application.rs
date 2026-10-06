use openmls_traits::signatures::Signer;

use crate::storage::OpenMlsProvider;

use super::{errors::CreateMessageError, *};

impl MlsGroup {
    // === Application messages ===

    /// Creates an application message.
    /// Returns `CreateMessageError::MlsGroupStateError::UseAfterEviction`
    /// if the member is no longer part of the group.
    /// Returns `CreateMessageError::MlsGroupStateError::PendingProposal` if pending proposals
    /// exist. In that case `.process_pending_proposals()` must be called first
    /// and incoming messages from the DS must be processed afterwards.
    pub fn create_message<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        message: &[u8],
    ) -> Result<MlsMessageOut, CreateMessageError> {
        if !self.is_active() {
            return Err(CreateMessageError::GroupStateError(
                MlsGroupStateError::UseAfterEviction,
            ));
        }
        if !self.proposal_store().is_empty() {
            return Err(CreateMessageError::GroupStateError(
                MlsGroupStateError::PendingProposal,
            ));
        }

        let authenticated_content = AuthenticatedContent::new_application(
            self.own_leaf_index(),
            &self.aad,
            message,
            self.context(),
            signer,
        )?;
        let ciphertext = self
            .encrypt(authenticated_content, provider)
            // We know the application message is wellformed and we have the key material of the current epoch
            .map_err(|_| LibraryError::custom("Malformed plaintext"))?;

        self.reset_aad();
        Ok(MlsMessageOut::from_private_message(
            ciphertext,
            self.version(),
        ))
    }

    /// Creates an application message. Returns
    /// `CreateMessageError::MlsGroupStateError::UseAfterEviction` if the member
    /// is no longer part of the group. Does not return
    /// `CreateMessageError::MlsGroupStateError::PendingProposal` if pending
    /// proposals exist. This function does not block a client from sending content
    /// while a proposal is inflight. Developers must handle the risk to confidentiality
    /// themselves.
    // #[cfg(feature = "demls-extension-inflight-proposals")]
    pub fn create_message_bypassing_proposal_safety<P: OpenMlsProvider>(
        &mut self,
        provider: &P,
        signer: &impl Signer,
        msg: &[u8],
    ) -> Result<MlsMessageOut, errors::CreateBypassMessageError<P::StorageError>> {
        let all: Vec<QueuedProposal> = self.pending_proposals().cloned().collect();

        for p in &all {
            self.remove_pending_proposal(provider.storage(), &p.proposal_reference())?;
        }

        // CRITICAL: A failure in this section results in a forked group.
        let result = self.create_message(provider, signer, msg);
        for p in all {
            self.store_pending_proposal(provider.storage(), p)
                .map_err(errors::CreateBypassMessageError::StorageError)?; // always restore
        }
        // CRITICAL: End
        Ok(result?)
    }
}
