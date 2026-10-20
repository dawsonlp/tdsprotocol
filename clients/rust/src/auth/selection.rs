//! One authentication selection belongs to a comparable connection snapshot.
use super::WindowsAuth;
use crate::entra::EntraLogin;
use std::fmt;
use zeroize::Zeroizing;

#[derive(Clone, PartialEq, Eq)]
pub struct SqlCredentials {
    pub user: String,
    pub password: Zeroizing<String>,
}
impl SqlCredentials {
    pub fn new(user: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            password: Zeroizing::new(password.into()),
        }
    }
}
impl fmt::Debug for SqlCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqlCredentials([redacted])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authentication {
    Sql(SqlCredentials),
    Windows(WindowsAuth),
    Entra(EntraLogin),
}
impl Authentication {
    pub fn sql(user: impl Into<String>, password: impl Into<String>) -> Self {
        Self::Sql(SqlCredentials::new(user, password))
    }
    pub fn sql_credentials(&self) -> Option<&SqlCredentials> {
        if let Self::Sql(value) = self {
            Some(value)
        } else {
            None
        }
    }
    pub fn sql_credentials_mut(&mut self) -> Option<&mut SqlCredentials> {
        if let Self::Sql(value) = self {
            Some(value)
        } else {
            None
        }
    }
    pub fn windows(&self) -> Option<&WindowsAuth> {
        if let Self::Windows(value) = self {
            Some(value)
        } else {
            None
        }
    }
    pub(crate) fn compatible_with(&self, previous: &Self) -> bool {
        match (self, previous) {
            (Self::Sql(a), Self::Sql(b)) => a.user == b.user,
            (Self::Windows(a), Self::Windows(b)) => a.compatible_with(b),
            (Self::Entra(a), Self::Entra(b)) => a == b,
            _ => false,
        }
    }
    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::Sql(value) => !value.user.is_empty(),
            Self::Windows(_) => true,
            Self::Entra(value) => value.valid(),
        }
    }
}
