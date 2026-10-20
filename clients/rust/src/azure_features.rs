//! Diagnostic requests are not implemented capabilities. Every explicit request
//! warns; a server that enables one makes the physical opening fail closed.
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AzureFeature {
    GlobalTransactions,
    AzureSqlSupport,
    DnsCaching,
    EnhancedRouting,
}
impl AzureFeature {
    pub fn id(self) -> u8 {
        match self {
            Self::GlobalTransactions => 5,
            Self::AzureSqlSupport => 8,
            Self::DnsCaching => 11,
            Self::EnhancedRouting => 15,
        }
    }
    pub(crate) fn from_id(id: u8) -> Option<Self> {
        Some(match id {
            5 => Self::GlobalTransactions,
            8 => Self::AzureSqlSupport,
            11 => Self::DnsCaching,
            15 => Self::EnhancedRouting,
            _ => return None,
        })
    }
    pub(crate) fn request(self) -> Vec<u8> {
        if self == Self::AzureSqlSupport {
            vec![1]
        } else {
            vec![]
        }
    }
}
impl fmt::Display for AzureFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::GlobalTransactions => "global transactions",
            Self::AzureSqlSupport => "Azure SQL failover-partner support",
            Self::DnsCaching => "Azure DNS caching",
            Self::EnhancedRouting => "enhanced routing",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeatureRequestWarning {
    pub feature: AzureFeature,
}
impl fmt::Display for FeatureRequestWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "requested unimplemented feature: {}; opening will fail if the server enables it",
            self.feature
        )
    }
}

/// Explicit diagnostic switches, all off by default. Absent/disabled ACKs may
/// complete login; an enabled ACK is an error, including in a diagnostic test.
/// These fields never opt into a permissive session or automatic retry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AzureFeatureProbes {
    pub azure_sql_support: bool,
    pub dns_caching: bool,
    pub enhanced_routing: bool,
    pub global_transactions: bool,
}
impl AzureFeatureProbes {
    /// Inspectable before opening, even without an observation callback.
    pub fn warnings(self) -> Vec<FeatureRequestWarning> {
        [
            (self.global_transactions, AzureFeature::GlobalTransactions),
            (self.azure_sql_support, AzureFeature::AzureSqlSupport),
            (self.dns_caching, AzureFeature::DnsCaching),
            (self.enhanced_routing, AzureFeature::EnhancedRouting),
        ]
        .into_iter()
        .filter_map(|(asked, feature)| asked.then_some(FeatureRequestWarning { feature }))
        .collect()
    }
}
