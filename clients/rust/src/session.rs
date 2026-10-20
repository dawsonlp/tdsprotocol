//! One session belongs to the connection, shared by all its channels.
//! Changes are authoritative only after the corresponding token is decoded.

use crate::{
    Error, ErrorKind, Result, packet,
    tokens::{EnvironmentChange, SqlText},
};
use std::collections::BTreeMap;

/// The server owns these state meanings. Keep its initial values, latest values
/// and per-state sequence numbers; never infer recoverability from SQL text.
/// MS-TDS §§2.2.6.4 and 2.2.7.21; shared policy: Python `tds.session.Recovery`.
#[derive(Clone, Debug)]
pub(crate) struct Recovery {
    initial: Session,
    initial_states: BTreeMap<u8, Vec<u8>>,
    states: BTreeMap<u8, Vec<u8>>,
    sequences: BTreeMap<u8, u32>,
    blocked: BTreeMap<u8, Vec<u8>>,
    exhausted: bool,
}
impl Recovery {
    pub fn new(initial: Session, bytes: &[u8]) -> Result<Self> {
        let mut reader = crate::wire::Reader::new(bytes);
        let initial_states: BTreeMap<_, _> = crate::tokens::states(&mut reader, bytes.len())
            .map_err(|e| {
                if let ErrorKind::Incomplete { offset, .. } = e.kind {
                    Error::malformed(offset, "truncated recovery acknowledgement")
                } else {
                    e
                }
            })?
            .into_iter()
            .collect();
        reader.end()?;
        Ok(Self {
            initial,
            states: initial_states.clone(),
            initial_states,
            sequences: BTreeMap::new(),
            blocked: BTreeMap::new(),
            exhausted: false,
        })
    }
    pub fn follow(&mut self, change: &crate::tokens::SessionStateChange) {
        self.exhausted |= change.sequence == u32::MAX;
        for (id, value) in &change.states {
            if self
                .sequences
                .get(id)
                .is_some_and(|seq| *seq >= change.sequence)
            {
                continue;
            }
            self.sequences.insert(*id, change.sequence);
            self.states.insert(*id, value.clone());
            if change.status & 1 != 0 {
                self.blocked.remove(id);
            } else {
                self.blocked.insert(*id, value.clone());
            }
        }
    }
    pub fn reset(&mut self) {
        self.states.clone_from(&self.initial_states);
        self.blocked.clear(); // exhaustion and per-state sequence history survive reset
    }
    pub fn refusal(&self) -> Option<String> {
        if self.exhausted {
            return Some(
                "session state sequence reached FFFFFFFF; recovery is off for this connection"
                    .into(),
            );
        }
        if self.blocked.is_empty() {
            return None;
        }
        Some(
            self.blocked
                .iter()
                .map(|(id, bytes)| {
                    // SQL Server's reason state is observational, not specified by TDS.
                    let reason = if *id == 254 {
                        match bytes.as_slice() {
                            [3, 0, 0, 0] => "session killed during a request",
                            [4, 0, 0, 0] => "a transaction is open",
                            [5, 0, 0, 0] => "a temporary table exists",
                            [13, 0, 0, 0] => "session impersonates another login",
                            _ => "unknown SQL Server reason",
                        }
                    } else {
                        "opaque server state"
                    };
                    format!("server marked state {id} not recoverable: {reason}")
                })
                .collect::<Vec<_>>()
                .join("; "),
        )
    }
    pub fn data(&self, current: &Session, reset: bool) -> Result<Vec<u8>> {
        let (current, values) = if reset {
            (&self.initial, &self.initial_states)
        } else {
            (current, &self.states)
        };
        let initial = snapshot(
            &self.initial.database,
            &self.initial.collation,
            &self.initial.language,
            self.initial_states.iter().filter(|(_, v)| !v.is_empty()),
        )?;
        let empty = SqlText::default();
        let now = snapshot(
            if current.database == self.initial.database {
                &empty
            } else {
                &current.database
            },
            if current.collation == self.initial.collation {
                &[]
            } else {
                &current.collation
            },
            if current.language == self.initial.language {
                &empty
            } else {
                &current.language
            },
            values.iter().filter(|(id, v)| {
                **id != 254 && !v.is_empty() && self.initial_states.get(id) != Some(v)
            }),
        )?;
        let mut out = Vec::new();
        for bytes in [initial, now] {
            out.extend(
                u32::try_from(bytes.len())
                    .map_err(|_| Error::new(ErrorKind::Limit("recovery snapshot")))?
                    .to_le_bytes(),
            );
            out.extend(bytes);
        }
        Ok(out)
    }
    /// A successful recovery becomes a new physical epoch: sequence numbers
    /// restart, but the original login baseline and latest state values persist.
    pub fn adopted(&self) -> Self {
        Self {
            sequences: BTreeMap::new(),
            blocked: BTreeMap::new(),
            exhausted: false,
            ..self.clone()
        }
    }
}
fn snapshot<'a>(
    database: &SqlText,
    collation: &[u8],
    language: &SqlText,
    states: impl Iterator<Item = (&'a u8, &'a Vec<u8>)>,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    snapshot_text(&mut out, database)?;
    out.push(
        u8::try_from(collation.len())
            .map_err(|_| Error::new(ErrorKind::Limit("recovery collation")))?,
    );
    out.extend(collation);
    snapshot_text(&mut out, language)?;
    for (id, value) in states {
        out.push(*id);
        if value.len() < 255 {
            out.push(value.len() as u8);
        } else {
            out.push(255);
            out.extend(
                u32::try_from(value.len())
                    .map_err(|_| Error::new(ErrorKind::Limit("recovery state")))?
                    .to_le_bytes(),
            );
        }
        out.extend(value);
    }
    Ok(out)
}
fn snapshot_text(out: &mut Vec<u8>, text: &SqlText) -> Result<()> {
    out.push(
        u8::try_from(text.0.len()).map_err(|_| Error::new(ErrorKind::Limit("recovery text")))?,
    );
    out.extend(text.0.iter().flat_map(|c| c.to_le_bytes()));
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Session {
    pub database: SqlText,
    pub language: SqlText,
    pub packet_size: usize,
    pub collation: Vec<u8>,
    pub transaction: u64,
    pub server_version: Option<[u8; 4]>,
    pub features: BTreeMap<u8, Vec<u8>>,
    /// Explicit unsupported requests, retained even when observation is off.
    pub feature_warnings: Vec<crate::azure_features::FeatureRequestWarning>,
    pub session_id: u16,
    pub tls_version: Option<rustls::ProtocolVersion>,
}
impl Default for Session {
    fn default() -> Self {
        Self {
            database: SqlText::default(),
            language: SqlText::default(),
            packet_size: packet::DEFAULT_SIZE,
            collation: Vec::new(),
            transaction: 0,
            server_version: None,
            features: BTreeMap::new(),
            feature_warnings: Vec::new(),
            session_id: 0,
            tls_version: None,
        }
    }
}
impl Session {
    /// RESET_COMPLETE restores login environment fields. Transaction state is
    /// governed by its own announcements: distributed transactions are exempt
    /// from RESETCONNECTION, as is the server's transaction isolation level.
    pub(crate) fn restore(&mut self, login: &Self) {
        self.database = login.database.clone();
        self.language = login.language.clone();
        self.packet_size = login.packet_size;
        self.collation = login.collation.clone();
    }
    pub(crate) fn apply(&mut self, change: &EnvironmentChange) -> Result<()> {
        match change {
            EnvironmentChange::Text { kind: 1, new, .. } => self.database = new.clone(),
            EnvironmentChange::Text { kind: 2, new, .. } => self.language = new.clone(),
            EnvironmentChange::Text { kind: 4, new, .. } => {
                let n = new
                    .to_string()
                    .ok()
                    .and_then(|s| s.parse::<usize>().ok())
                    .filter(|n| (512..=packet::MAX_SIZE).contains(n))
                    .ok_or_else(|| Error::malformed(0, "announced packet size"))?;
                self.packet_size = n;
            }
            EnvironmentChange::Bytes { kind: 7, new, .. } if new.len() == 5 => {
                self.collation = new.clone()
            }
            EnvironmentChange::Bytes { kind: 8, new, .. } if new.len() == 8 => {
                let mut b = [0; 8];
                b.copy_from_slice(new);
                self.transaction = u64::from_le_bytes(b);
            }
            EnvironmentChange::Bytes {
                kind: 9 | 10 | 17,
                new,
                ..
            } if new.is_empty() => self.transaction = 0,
            _ => return Err(Error::new(ErrorKind::Unsupported("session announcement"))),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::SessionStateChange;
    #[test]
    fn recovery_snapshots_match_python_and_the_mstds_example() {
        let initial = Session {
            database: "master".into(),
            language: "us_english".into(),
            collation: vec![9, 4, 0xd0, 0, 0x34],
            ..Session::default()
        };
        let mut recovery = Recovery::new(
            initial.clone(),
            include_bytes!("../tests/fixtures/recovery/initial.bin"),
        )
        .unwrap();
        recovery.follow(&SessionStateChange {
            sequence: 1,
            status: 1,
            states: vec![(9, vec![0x28, 0x23, 0, 0])],
        });
        assert_eq!(
            recovery.data(&initial, false).unwrap(),
            include_bytes!("../tests/fixtures/recovery/recovery.bin")
        );
        let current = Session {
            database: "tempdb".into(),
            language: "Deutsch".into(),
            ..initial.clone()
        };
        assert_ne!(
            recovery.data(&current, false).unwrap(),
            recovery.data(&current, true).unwrap()
        );
        recovery.reset();
        assert_eq!(
            recovery.data(&current, true).unwrap(),
            recovery.data(&initial, false).unwrap()
        );
    }
    #[test]
    fn per_state_sequences_refusal_reset_and_exhaustion_follow_python() {
        let mut recovery = Recovery::new(Session::default(), &[]).unwrap();
        let change = |sequence, status, value| SessionStateChange {
            sequence,
            status,
            states: vec![(254, value)],
        };
        recovery.follow(&change(5, 0, vec![4, 0, 0, 0]));
        recovery.follow(&change(4, 1, vec![0; 4])); // older news cannot clear a refusal
        assert!(recovery.refusal().unwrap().contains("transaction is open"));
        recovery.follow(&change(6, 1, vec![0; 4]));
        assert!(recovery.refusal().is_none());
        recovery.follow(&change(7, 0, vec![5, 0, 0, 0]));
        recovery.reset();
        assert!(recovery.refusal().is_none());
        recovery.follow(&change(u32::MAX, 1, vec![0; 4]));
        recovery.reset();
        assert!(recovery.refusal().unwrap().contains("FFFFFFFF"));
    }
    #[test]
    fn reset_restores_environment_but_transaction_waits_for_its_own_announcement() {
        let login = Session::default();
        let mut session = Session {
            database: SqlText("changed".encode_utf16().collect()),
            language: SqlText("French".encode_utf16().collect()),
            packet_size: 512,
            collation: vec![1; 5],
            transaction: 17,
            session_id: 42,
            ..Session::default()
        };
        session.restore(&login);
        assert_eq!(session.database, login.database);
        assert_eq!(session.language, login.language);
        assert_eq!(session.packet_size, login.packet_size);
        assert_eq!(session.collation, login.collation);
        assert_eq!((session.transaction, session.session_id), (17, 42));
        session
            .apply(&EnvironmentChange::Bytes {
                kind: 10,
                new: vec![],
                old: 17_u64.to_le_bytes().to_vec(),
            })
            .unwrap();
        assert_eq!(session.transaction, 0);
    }
}
