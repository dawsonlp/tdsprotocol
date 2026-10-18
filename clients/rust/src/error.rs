//! Errors retain the failing procedure and what is known about execution.
//! Raw request/LOGIN7 buffers are never attached. Server text is retained as
//! server data; Display prints its number/state/severity without echoing text.

use std::fmt;

use crate::tokens::ServerMessage;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub server: String,
    pub port: u16,
}
impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.server.contains(':') {
            write!(f, "[{}]:{}", self.server, self.port)
        } else {
            write!(f, "{}:{}", self.server, self.port)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Start,
    Hello,
    Secure,
    Login,
    Ready,
    Exchange,
    Cleanup,
    Close,
    Pool,
    Configuration,
    Recover,
}

/// Transmission is not proof that SQL executed, or that cancellation rolled it back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Execution {
    NotSent,
    PossiblyExecuted,
}

#[derive(Debug)]
pub enum ErrorKind {
    #[cfg(feature = "encryption")]
    Encryption(crate::encryption::Error),
    NotYetRead(&'static str),
    Parameter(&'static str),
    Configuration(crate::config::ConfigError),
    Incomplete {
        offset: usize,
        needed: usize,
    },
    Malformed {
        offset: usize,
        field: &'static str,
    },
    Unsupported(&'static str),
    Limit(&'static str),
    State(&'static str),
    Closed,
    Timeout,
    Canceled,
    SessionNotRecovered {
        reason: String,
        cause: Option<Box<Error>>,
    },
    Routed(Route),
    RepeatedRoute {
        from: Route,
        via: Route,
        target: Route,
    },
    /// The original failure remains inspectable even when teardown also fails.
    Cleanup {
        original: Box<Error>,
        cleanup: Box<Error>,
    },
    Io(std::io::Error),
    Capture(std::io::Error),
    Tls(rustls::Error),
    Server(Box<ServerMessage>),
    /// All nonfatal SQL errors, reported once after the complete response.
    ServerErrors(Vec<ServerMessage>),
    /// One cleanup failure may be observed by the owner and several close waiters.
    Shared(std::sync::Arc<Error>),
}

#[derive(Debug)]
pub struct Error {
    pub step: Step,
    pub execution: Execution,
    /// Application SQL may be unsent while LOGIN7 has changed a password.
    /// A lost login completion cannot establish which credential now works.
    pub password_change_uncertain: bool,
    pub kind: ErrorKind,
    /// Semantic record received before this failure; never raw request bytes.
    pub response: Option<Box<crate::response::FetchedResponse>>,
}

impl Error {
    /// Underlying failure shared by several channel/close waiters. This unwraps
    /// only Shared; Cleanup still exposes both original and cleanup failures.
    pub fn cause(&self) -> &Self {
        match &self.kind {
            ErrorKind::Shared(error) => error.cause(),
            _ => self,
        }
    }

    #[cfg(feature = "tokio")]
    pub(crate) fn shared(error: std::sync::Arc<Error>) -> Self {
        let response = error.response.clone();
        Self {
            step: error.step,
            execution: error.execution,
            password_change_uncertain: error.password_change_uncertain,
            kind: ErrorKind::Shared(error),
            response,
        }
    }
    pub(crate) fn new(kind: ErrorKind) -> Self {
        Self {
            step: Step::Start,
            execution: Execution::NotSent,
            password_change_uncertain: false,
            kind,
            response: None,
        }
    }
    pub(crate) fn at(mut self, step: Step, execution: Execution) -> Self {
        self.step = step;
        self.execution = execution;
        self
    }
    pub(crate) fn malformed(offset: usize, field: &'static str) -> Self {
        Self::new(ErrorKind::Malformed { offset, field })
    }
    #[cfg(feature = "tokio")]
    pub(crate) fn canceled() -> Self {
        Self::new(ErrorKind::Canceled).at(Step::Cleanup, Execution::PossiblyExecuted)
    }
    #[cfg(feature = "tokio")]
    pub(crate) fn cleanup(original: Error, cleanup: Error) -> Self {
        let response = original
            .response
            .clone()
            .or_else(|| cleanup.response.clone());
        let execution = if original.execution == Execution::PossiblyExecuted
            || cleanup.execution == Execution::PossiblyExecuted
        {
            Execution::PossiblyExecuted
        } else {
            Execution::NotSent
        };
        Self {
            step: Step::Cleanup,
            execution,
            password_change_uncertain: original.password_change_uncertain
                || cleanup.password_change_uncertain,
            kind: ErrorKind::Cleanup {
                original: Box::new(original),
                cleanup: Box::new(cleanup),
            },
            response,
        }
    }
    #[cfg(feature = "tokio")]
    pub(crate) fn with_response(mut self, response: crate::response::FetchedResponse) -> Self {
        self.response = Some(Box::new(response));
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let ErrorKind::Shared(error) = &self.kind {
            return error.fmt(f);
        }
        if self.password_change_uncertain {
            write!(
                f,
                "password-changing login did not complete; the server password may already have changed; "
            )?;
        }
        write!(f, "TDS {:?}: ", self.step)?;
        match &self.kind {
            #[cfg(feature = "encryption")]
            ErrorKind::Encryption(e) => e.fmt(f),
            ErrorKind::NotYetRead(reason) => write!(f, "not yet read: {reason}"),
            ErrorKind::Parameter(reason) => write!(f, "parameter refused: {reason}"),
            ErrorKind::Configuration(error) => error.fmt(f),
            ErrorKind::Shared(error) => error.fmt(f),
            ErrorKind::Incomplete { offset, needed } => {
                write!(f, "incomplete input at {offset}, need {needed} bytes")
            }
            ErrorKind::Malformed { offset, field } => {
                write!(f, "malformed {field} at byte {offset}")
            }
            ErrorKind::Unsupported(what) => write!(f, "unsupported: {what}"),
            ErrorKind::Limit(what) => write!(f, "limit exceeded: {what}"),
            ErrorKind::State(why) => f.write_str(why),
            ErrorKind::Closed => f.write_str("connection or channel closed"),
            ErrorKind::Timeout if self.step == Step::Cleanup => {
                f.write_str("cancellation cleanup deadline expired")
            }
            ErrorKind::Timeout => f.write_str("connection deadline expired"),
            ErrorKind::Canceled => f.write_str("exchange cancellation"),
            ErrorKind::SessionNotRecovered { reason, cause } => {
                write!(f, "session not recovered: {reason}")?;
                if let Some(cause) = cause {
                    write!(f, "; {cause}")?;
                }
                Ok(())
            }
            ErrorKind::Routed(route) => write!(f, "login routed to {route}"),
            ErrorKind::RepeatedRoute { from, via, target } => write!(
                f,
                "routed a second time: {from} → {via} → {target}; only one redirect is followed"
            ),
            ErrorKind::Cleanup { original, cleanup } => {
                write!(f, "{original}; cleanup also failed: {cleanup}")
            }
            ErrorKind::Io(e) => e.fmt(f),
            ErrorKind::Capture(_) => {
                f.write_str("saved conversation recording failed; connection discarded")
            }
            ErrorKind::Tls(e) => e.fmt(f),
            ErrorKind::Server(e) => write!(
                f,
                "server error {} (state {}, severity {})",
                e.number, e.state, e.severity
            ),
            ErrorKind::ServerErrors(errors) => {
                f.write_str("server errors")?;
                for error in errors {
                    write!(
                        f,
                        " {} (state {}, severity {})",
                        error.number, error.state, error.severity
                    )?;
                }
                Ok(())
            }
        }?;
        if self.execution == Execution::PossiblyExecuted {
            f.write_str("; request execution may have begun")?;
        }
        Ok(())
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            ErrorKind::Configuration(error) => Some(error),
            ErrorKind::Io(e) => Some(e),
            ErrorKind::Capture(e) => Some(e),
            ErrorKind::Tls(e) => Some(e),
            ErrorKind::Cleanup { cleanup, .. } => Some(cleanup.as_ref()),
            ErrorKind::Shared(error) => Some(error.as_ref()),
            ErrorKind::SessionNotRecovered { cause, .. } => cause.as_deref().map(|e| e as _),
            _ => None,
        }
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::new(ErrorKind::Io(e))
    }
}
impl From<rustls::Error> for Error {
    fn from(e: rustls::Error) -> Self {
        Self::new(ErrorKind::Tls(e))
    }
}

#[cfg(feature = "encryption")]
impl From<crate::encryption::Error> for Error {
    fn from(e: crate::encryption::Error) -> Self {
        Self::new(ErrorKind::Encryption(e))
    }
}
