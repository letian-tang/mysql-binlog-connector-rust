use crate::{binlog_error::BinlogError, constants, ext::buf_ext::BufExt};

pub struct AuthSha2RsaPasswordCommand {
    pub rsa_res: Vec<u8>,
    pub password: String,
    pub scramble: String,
}

impl AuthSha2RsaPasswordCommand {
    pub fn to_bytes(&mut self) -> Result<Vec<u8>, BinlogError> {
        let mut password_buf = self.password.as_bytes().to_vec();
        password_buf.push(constants::NULL_TERMINATOR);
        let encrypted_password = password_buf.xor(self.scramble.as_bytes().to_vec());

        Ok(mysql_common::crypto::encrypt(
            &encrypted_password,
            self.rsa_res.as_slice(),
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ephemeral test public key; no private key is stored.
    const PUBLIC_KEY: &[u8] = br#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7k8Z8chWE2k0SffJcZDy
kq0eKQ5QoNxUxCyCI5veESnJOdW0cafBV80IKwrAwEyQV1Yrqb6+Cvvpw5MgTImU
sqGqM0axV6sivDSBL/kmi0cZ5x0pIm0Qo24lDdwB5DPUmlm/delGHmIanH+x1pkC
faxHJXc0FthVAHi6MWdHEtI9Qw0f1Gryr8kizVovv9so9qvQTUVATcw/0uqLPGzy
MVpQOKqVy1ZPwLfygIvVPoUrzmHFdDRHKfXm17zPm4MLYfPuAqXFiwn11NxjUXSU
uLcZkPKcMhJtXI3YZHXZ3tfSAJjHbQIrLT7/nlCoi/yg9RunXaOLkxqQAR9XRE8e
lwIDAQAB
-----END PUBLIC KEY-----
"#;

    fn command(key: &[u8], password: String) -> AuthSha2RsaPasswordCommand {
        AuthSha2RsaPasswordCommand {
            rsa_res: key.to_vec(),
            password,
            scramble: "0123456789abcdefghij".into(),
        }
    }

    #[test]
    fn rsa_password_produces_randomized_modulus_sized_ciphertext() {
        let mut command = command(PUBLIC_KEY, "test-password".into());
        let first = command.to_bytes().unwrap();
        let second = command.to_bytes().unwrap();
        assert_eq!(first.len(), 256);
        assert_eq!(second.len(), 256);
        assert_ne!(first, second);
    }

    #[test]
    fn invalid_public_key_returns_authentication_error() {
        let error = command(b"invalid PEM", "password".into())
            .to_bytes()
            .unwrap_err();
        assert!(matches!(error, BinlogError::AuthenticationEncryption(_)));
    }

    #[test]
    fn oversized_password_returns_authentication_error() {
        let error = command(PUBLIC_KEY, "x".repeat(300)).to_bytes().unwrap_err();
        assert!(matches!(error, BinlogError::AuthenticationEncryption(_)));
    }
}
