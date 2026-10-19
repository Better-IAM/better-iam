//! The service and the futures of its public methods are `Send`, so web frameworks can run them on any worker.

use better_iam_auth::AuthService;
use better_iam_core::CredentialInput;
use serde_json::Value;

fn send<T: Send>(_: &T) {}

#[allow(dead_code)]
fn futures_are_send(auth: &AuthService, input: &Value, credential: &CredentialInput) {
    send(auth);
    send(&auth.sign_up(input));
    send(&auth.sign_in(input));
    send(&auth.authenticate(credential));
    send(&auth.get_session(credential));
    send(&auth.list_sessions(credential));
    send(&auth.revoke_session(credential, input));
    send(&auth.revoke_other_sessions(credential));
    send(&auth.sign_out(credential));
    send(&auth.list_security_events(credential, input));
    send(&auth.list_trusted_devices(credential));
    send(&auth.revoke_trusted_device(credential, input));
    send(&auth.revoke_trusted_devices(credential));
    send(&auth.request_email_verification(input));
    send(&auth.verify_email(input));
    send(&auth.request_password_reset(input));
    send(&auth.reset_password(input));
    send(&auth.change_password(credential, input));
    send(&auth.reauthenticate(credential, input));
    send(&auth.request_email_change(credential, input));
    send(&auth.confirm_email_change(input));
    send(&auth.start_phone_verification(credential, input));
    send(&auth.confirm_phone_verification(credential, input));
    send(&auth.start_passwordless(input));
    send(&auth.finish_passwordless(input));
    send(&auth.verify_mfa(input));
    send(&auth.request_mfa_code(input));
    send(&auth.recover_mfa(input));
    send(&auth.mfa_status(credential));
    send(&auth.regenerate_recovery_codes(credential));
    send(&auth.disable_mfa(credential));
    send(&auth.begin_passkey_registration(credential));
    send(&auth.finish_passkey_registration(credential, input));
    send(&auth.begin_passkey_authentication(input));
    send(&auth.finish_passkey_authentication(input));
    send(&auth.begin_passkey_mfa(input));
    send(&auth.finish_passkey_mfa(input));
    send(&auth.list_passkeys(credential));
    send(&auth.rename_passkey(credential, input));
    send(&auth.delete_passkey(credential, input));
    send(&auth.dispatch_outbox(None));
    send(&auth.settle_bookkeeping());
    send(&auth.validate_session_id("ses_1"));
}

#[test]
fn compiles() {}
