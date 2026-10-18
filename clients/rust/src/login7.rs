//! LOGIN7 has a 94-byte fixed area and an offset/count table for UTF-16 fields.
//! Reference: `docs/design/3-reference/login7.md`; MS-TDS v20260617 §2.2.6.4.
//! Password nibble swapping is obfuscation only. TLS must already be verified.

use crate::{Error, ErrorKind, Result, wire};

pub const TDS_7_4: u32 = 0x74000004;

/// No Debug implementation: this value holds authentication material.
pub struct Login {
    pub user: String,
    pub password: String,
    pub new_password: String,
    pub database: String,
    pub host_name: String,
    pub server_name: String,
    pub process_id: u32,
    pub app_name: String,
    pub language: String,
    pub odbc: bool,
    /// Availability-group routing hint, not write permission enforcement.
    pub read_only_intent: bool,
    /// Request server-reported state for eligible recovery.
    pub session_recovery: bool,
    /// Request native JSON results; parameters always use strict UTF-8.
    pub json_support: bool,
    /// Zero disables; versions one/two preserve server downgrades explicitly.
    pub vector_support: u8,
    pub data_classification: u8,
    /// Advertise exact UTF-8 transport rather than server substitution.
    pub utf8_support: bool,
    pub recovery_data: Option<Vec<u8>>,
}

impl Default for Login {
    fn default() -> Self {
        Self {
            user: String::new(),
            password: String::new(),
            new_password: String::new(),
            database: String::new(),
            host_name: String::new(),
            server_name: String::new(),
            process_id: 0,
            app_name: "tds (rust)".into(),
            language: String::new(),
            odbc: true,
            read_only_intent: false,
            session_recovery: false,
            json_support: false,
            vector_support: 0,
            data_classification: 0,
            utf8_support: false,
            recovery_data: None,
        }
    }
}

impl Login {
    pub(crate) fn requested_features(&self) -> Result<std::collections::BTreeMap<u8, Vec<u8>>> {
        if self.vector_support > 2 || self.data_classification > 2 {
            return Err(Error::new(ErrorKind::Parameter(
                "unsupported requested feature version",
            )));
        }
        let mut features = std::collections::BTreeMap::new();
        if self.session_recovery {
            features.insert(1, self.recovery_data.clone().unwrap_or_default());
        } else if self.recovery_data.is_some() {
            return Err(Error::new(ErrorKind::State(
                "recovery data without its login feature",
            )));
        }
        if self.data_classification != 0 {
            features.insert(9, vec![self.data_classification]);
        }
        if self.utf8_support {
            features.insert(10, vec![1]);
        }
        if self.json_support {
            features.insert(13, vec![1]);
        }
        if self.vector_support != 0 {
            features.insert(14, vec![self.vector_support]);
        }
        Ok(features)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let features = self.requested_features()?;
        let mut out = vec![0; 94];
        out[4..8].copy_from_slice(&TDS_7_4.to_le_bytes());
        out[8..12].copy_from_slice(&4096_u32.to_le_bytes());
        out[12..16].copy_from_slice(&0x00010000_u32.to_le_bytes());
        out[16..20].copy_from_slice(&self.process_id.to_le_bytes());
        out[24] = 0xe0; // report database/language changes; initial database must succeed
        out[25] = 1 | if self.odbc { 2 } else { 0 }; // initial language must succeed; ODBC session defaults
        out[26] = if self.read_only_intent { 0x20 } else { 0 };
        out[27] = u8::from(!self.new_password.is_empty()); // fChangePassword
        out[32..36].copy_from_slice(&0x0409_u32.to_le_bytes()); // client LCID, as in Python; session language is separate
        let fields = [
            self.host_name.as_str(),
            &self.user,
            &self.password,
            &self.app_name,
            &self.server_name,
            "",
            "tds (rust)",
            &self.language,
            &self.database,
        ];
        for (index, text) in fields.into_iter().enumerate() {
            let mut data = wire::utf16(text);
            if index == 5 && !features.is_empty() {
                data = vec![0; 4];
            }
            let offset = u16::try_from(out.len())
                .map_err(|_| Error::new(ErrorKind::Limit("LOGIN7 offsets")))?;
            let count = u16::try_from(if index == 5 {
                data.len()
            } else {
                data.len() / 2
            })
            .map_err(|_| Error::new(ErrorKind::Limit("LOGIN7 text")))?;
            let p = 36 + index * 4;
            out[p..p + 2].copy_from_slice(&offset.to_le_bytes());
            out[p + 2..p + 4].copy_from_slice(&count.to_le_bytes());
            if index == 2 {
                for b in &mut data {
                    *b = b.rotate_left(4) ^ 0xa5;
                }
            }
            out.extend(data);
        }
        if out.len() > usize::from(u16::MAX) {
            return Err(Error::new(ErrorKind::Limit("LOGIN7 total length")));
        }
        // Empty Windows-auth/attach-file entries and the start of new-password
        // data point here, matching the shared LOGIN7 definition.
        let end = (out.len() as u16).to_le_bytes();
        for at in [78, 82, 86] {
            out[at..at + 2].copy_from_slice(&end);
        }
        let count = u16::try_from(self.new_password.encode_utf16().count())
            .map_err(|_| Error::new(ErrorKind::Limit("LOGIN7 new password")))?;
        out[88..90].copy_from_slice(&count.to_le_bytes());
        for byte in wire::utf16(&self.new_password) {
            out.push(byte.rotate_left(4) ^ 0xa5);
        }
        if out.len() > usize::from(u16::MAX) {
            return Err(Error::new(ErrorKind::Limit("LOGIN7 total length")));
        }
        if !features.is_empty() {
            out[27] |= 0x10;
            let pointer = usize::from(u16::from_le_bytes(out[56..58].try_into().unwrap()));
            let feature_offset = out.len() as u32;
            out[pointer..pointer + 4].copy_from_slice(&feature_offset.to_le_bytes());
            for (id, data) in features {
                out.push(id);
                out.extend(
                    u32::try_from(data.len())
                        .map_err(|_| Error::new(ErrorKind::Limit("LOGIN7 feature data")))?
                        .to_le_bytes(),
                );
                out.extend(data);
            }
            out.push(0xff);
        }
        let len = u32::try_from(out.len())
            .map_err(|_| Error::new(ErrorKind::Limit("LOGIN7 total length")))?;
        out[..4].copy_from_slice(&len.to_le_bytes());
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn password_change_matches_python_and_masks_both_credentials() {
        let login = Login {
            user: "fixture-user".into(),
            password: "not-a-real-password".into(),
            new_password: "also-artificial-λ".into(),
            database: "fixture-database".into(),
            host_name: "fixture-host".into(),
            server_name: "fixture-server".into(),
            process_id: 1234,
            session_recovery: true,
            ..Login::default()
        };
        let bytes = login.encode().unwrap();
        assert_eq!(
            bytes,
            include_bytes!("../tests/fixtures/login7/password-change.bin")
        );
        assert_eq!(bytes[27], 0x11);
        let redacted = crate::capture::without_password(crate::packet::LOGIN, &bytes);
        for field in [44, 86] {
            let offset = usize::from(u16::from_le_bytes(
                bytes[field..field + 2].try_into().unwrap(),
            ));
            let length = usize::from(u16::from_le_bytes(
                bytes[field + 2..field + 4].try_into().unwrap(),
            )) * 2;
            assert!(length > 0);
            assert!(redacted[offset..offset + length].iter().all(|b| *b == 0));
        }
    }
    #[test]
    fn login_options_match_the_shared_python_definition_exactly() {
        let default = Login {
            user: "fixture-user".into(),
            password: "not-a-real-password".into(),
            database: "fixture-database".into(),
            host_name: "fixture-host".into(),
            server_name: "fixture-server".into(),
            process_id: 1234,
            ..Login::default()
        };
        let bytes = default.encode().unwrap();
        assert_eq!(
            bytes,
            include_bytes!("../tests/fixtures/login7/default.bin")
        );
        assert_eq!(bytes[25], 3);
        assert_eq!(u16::from_le_bytes(bytes[66..68].try_into().unwrap()), 0); // language count
        let custom = Login {
            odbc: false,
            language: "Deutsch".into(),
            read_only_intent: true,
            app_name: "service-λ".into(),
            host_name: "machine-1".into(),
            ..default
        };
        let bytes = custom.encode().unwrap();
        assert_eq!(bytes, include_bytes!("../tests/fixtures/login7/custom.bin"));
        assert_eq!((bytes[25], bytes[26]), (1, 0x20));
    }
    #[test]
    fn recovery_extension_matches_python_initial_and_recovery_logins() {
        for (data, expected) in [
            (
                None,
                include_bytes!("../tests/fixtures/recovery/login.bin").as_slice(),
            ),
            (
                Some(include_bytes!("../tests/fixtures/recovery/recovery.bin").to_vec()),
                include_bytes!("../tests/fixtures/recovery/recover-login.bin").as_slice(),
            ),
        ] {
            let login = Login {
                user: "fixture-user".into(),
                password: "not-a-real-password".into(),
                database: "fixture-database".into(),
                host_name: "fixture-host".into(),
                server_name: "fixture-server".into(),
                process_id: 1234,
                session_recovery: true,
                recovery_data: data,
                ..Login::default()
            };
            assert_eq!(login.encode().unwrap(), expected);
        }
    }
}
