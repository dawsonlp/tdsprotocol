//! Explicit transaction-manager requests, following Python `tds.transactions`.
//! MS-TDS §2.2.6.9. Each operation is one ordinary exchange. The server checks
//! nesting/savepoint rules; only received ENVCHANGE changes the local descriptor.
//! Nothing commits, rolls back, retries or lends transaction ownership implicitly.
use crate::{
    Error, ErrorKind, Result, SqlText,
    requests::{Context, Encoded, Request, headers},
};

#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Isolation {
    #[default]
    Unchanged = 0,
    ReadUncommitted = 1,
    ReadCommitted = 2,
    RepeatableRead = 3,
    Serializable = 4,
    Snapshot = 5,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Begin {
    pub isolation: Isolation,
    pub name: SqlText,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct End {
    pub name: SqlText,
    /// Begin another transaction in this same request, as Python's `begin=`.
    pub begin: Option<Begin>,
}
/// SQL transaction authority still belongs to the authenticated server principal.
/// These values describe wire requests, not Rust guards or transaction scopes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Transaction {
    Begin(Begin),
    Commit(End),
    Rollback(End),
    Save(SqlText),
    Promote,
    Propagate(Vec<u8>),
    CoordinatorAddress,
}
fn name(value: &SqlText, out: &mut Vec<u8>) -> Result<()> {
    let bytes = value
        .0
        .len()
        .checked_mul(2)
        .and_then(|n| u8::try_from(n).ok())
        .ok_or_else(|| {
            Error::new(ErrorKind::Parameter(
                "transaction name exceeds 127 UTF-16 units",
            ))
        })?;
    out.push(bytes);
    out.extend(value.0.iter().flat_map(|n| n.to_le_bytes()));
    Ok(())
}
fn begin(value: &Begin, out: &mut Vec<u8>) -> Result<()> {
    out.push(value.isolation as u8);
    name(&value.name, out)
}
impl Request for Transaction {
    fn label(&self) -> &'static str {
        "transaction manager"
    }
    fn encode_request(&self, context: &Context) -> Result<Encoded> {
        let mut body = headers(context.transaction, context.outstanding);
        let code: u16 = match self {
            Self::CoordinatorAddress => 0,
            Self::Propagate(_) => 1,
            Self::Begin(_) => 5,
            Self::Promote => 6,
            Self::Commit(_) => 7,
            Self::Rollback(_) => 8,
            Self::Save(_) => 9,
        };
        body.extend(code.to_le_bytes());
        match self {
            Self::Begin(value) => begin(value, &mut body)?,
            Self::Commit(value) | Self::Rollback(value) => {
                name(&value.name, &mut body)?;
                body.push(u8::from(value.begin.is_some()));
                if let Some(value) = &value.begin {
                    begin(value, &mut body)?;
                }
            }
            Self::Save(value) => name(value, &mut body)?,
            Self::Propagate(cookie) => {
                let n = u16::try_from(cookie.len()).map_err(|_| {
                    Error::new(ErrorKind::Parameter("transaction cookie exceeds u16"))
                })?;
                body.extend(n.to_le_bytes());
                body.extend(cookie);
            }
            Self::CoordinatorAddress => body.extend(0_u16.to_le_bytes()),
            Self::Promote => {}
        }
        Ok(Encoded {
            continuation: crate::requests::Continuation::None,
            kind: crate::packet::TRANSACTION,
            body,
            metadata: Vec::new(),
        })
    }
}
