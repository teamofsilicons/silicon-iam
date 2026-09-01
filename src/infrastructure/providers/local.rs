//! Side-effect-free local notification adapter.

use async_trait::async_trait;
use uuid::Uuid;

use crate::application::ports::{
    DeliveryError, DeliveryReceipt, EmailDelivery, EmailOtp, InvitationEmail, InvitationSms,
    SecurityNotice, SmsDelivery, SmsOtp,
};

#[derive(Clone, Copy)]
pub(super) struct LocalDelivery;

fn receipt() -> DeliveryReceipt {
    DeliveryReceipt {
        provider_message_id: format!("local_{}", Uuid::now_v7()),
    }
}

#[async_trait]
impl EmailDelivery for LocalDelivery {
    async fn send_otp(&self, _command: EmailOtp<'_>) -> Result<DeliveryReceipt, DeliveryError> {
        Ok(receipt())
    }

    async fn send_invitation(
        &self,
        _command: InvitationEmail<'_>,
    ) -> Result<DeliveryReceipt, DeliveryError> {
        Ok(receipt())
    }

    async fn send_security_notice(
        &self,
        _command: SecurityNotice<'_>,
    ) -> Result<DeliveryReceipt, DeliveryError> {
        Ok(receipt())
    }
}

#[async_trait]
impl SmsDelivery for LocalDelivery {
    async fn send_otp(&self, _command: SmsOtp<'_>) -> Result<DeliveryReceipt, DeliveryError> {
        Ok(receipt())
    }

    async fn send_security_notice(
        &self,
        _command: SecurityNotice<'_>,
    ) -> Result<DeliveryReceipt, DeliveryError> {
        Ok(receipt())
    }

    async fn send_invitation(
        &self,
        _command: InvitationSms<'_>,
    ) -> Result<DeliveryReceipt, DeliveryError> {
        Ok(receipt())
    }
}
