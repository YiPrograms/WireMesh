use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    Local,
    Oidc,
    Ldap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserIdentity {
    pub id: Uuid,
    pub provider_id: Option<Uuid>,
    pub kind: IdentityKind,
    pub external_id: String,
    pub current_email: String,
    pub active: bool,
    pub provider_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserStatus {
    pub manual_disabled: bool,
    pub soft_deleted: bool,
    pub identities: Vec<UserIdentity>,
}

impl UserStatus {
    pub fn ldap_disabled(&self) -> bool {
        let ldap: Vec<_> = self
            .identities
            .iter()
            .filter(|identity| identity.kind == IdentityKind::Ldap)
            .collect();
        !ldap.is_empty()
            && !ldap
                .iter()
                .any(|identity| identity.active && identity.provider_enabled)
    }

    pub fn disabled(&self) -> bool {
        self.soft_deleted || self.manual_disabled || self.ldap_disabled()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipSourceKind {
    Local,
    Oidc,
    Ldap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourcedMembership {
    pub group_id: Uuid,
    pub group_name: String,
    pub source_kind: MembershipSourceKind,
    pub source_id: Option<Uuid>,
    pub active: bool,
}

/// Returns group IDs and their contributing provenance.
///
/// Local membership is always effective. If the user has any LDAP identity,
/// only active LDAP memberships are considered external. Otherwise OIDC is
/// used. This is deliberately based on identity linkage, not provider health.
pub fn effective_groups(
    identities: &[UserIdentity],
    memberships: &[SourcedMembership],
) -> BTreeMap<Uuid, BTreeSet<MembershipSourceKind>> {
    let has_ldap = identities
        .iter()
        .any(|identity| identity.kind == IdentityKind::Ldap);

    let mut result = BTreeMap::<Uuid, BTreeSet<MembershipSourceKind>>::new();
    for membership in memberships.iter().filter(|membership| membership.active) {
        let effective = match membership.source_kind {
            MembershipSourceKind::Local => true,
            MembershipSourceKind::Ldap => has_ldap,
            MembershipSourceKind::Oidc => !has_ldap,
        };
        if effective {
            result
                .entry(membership.group_id)
                .or_default()
                .insert(membership.source_kind);
        }
    }
    result
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("email is empty")]
    EmptyEmail,
    #[error("email must contain one local part and one domain")]
    InvalidEmail,
    #[error("group name is empty")]
    EmptyGroup,
}

/// Product-level normalization used for unique account linking.
pub fn normalize_email(value: &str) -> Result<String, IdentityError> {
    let normalized = value.trim().to_lowercase();
    let (local, domain) = normalized
        .split_once('@')
        .ok_or(IdentityError::InvalidEmail)?;
    if normalized.is_empty() {
        return Err(IdentityError::EmptyEmail);
    }
    if local.is_empty()
        || domain.is_empty()
        || domain.contains('@')
        || local.chars().any(char::is_whitespace)
        || domain.chars().any(char::is_whitespace)
    {
        return Err(IdentityError::InvalidEmail);
    }
    Ok(normalized)
}

pub fn normalize_group_name(value: &str) -> Result<String, IdentityError> {
    let normalized = value.trim().to_lowercase();
    if normalized.is_empty() {
        Err(IdentityError::EmptyGroup)
    } else {
        Ok(normalized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(kind: IdentityKind, active: bool) -> UserIdentity {
        UserIdentity {
            id: Uuid::new_v4(),
            provider_id: None,
            kind,
            external_id: "subject".into(),
            current_email: "person@example.com".into(),
            active,
            provider_enabled: true,
        }
    }

    #[test]
    fn manual_disable_always_wins() {
        let status = UserStatus {
            manual_disabled: true,
            soft_deleted: false,
            identities: vec![identity(IdentityKind::Ldap, true)],
        };
        assert!(status.disabled());
        assert!(!status.ldap_disabled());
    }

    #[test]
    fn ldap_is_disabled_only_when_every_identity_is_inactive() {
        let status = UserStatus {
            manual_disabled: false,
            soft_deleted: false,
            identities: vec![
                identity(IdentityKind::Ldap, false),
                identity(IdentityKind::Ldap, true),
            ],
        };
        assert!(!status.disabled());
    }

    #[test]
    fn linked_ldap_suppresses_oidc_groups_but_not_local_groups() {
        let ldap_group = Uuid::new_v4();
        let oidc_group = Uuid::new_v4();
        let local_group = Uuid::new_v4();
        let memberships = vec![
            SourcedMembership {
                group_id: ldap_group,
                group_name: "engineering".into(),
                source_kind: MembershipSourceKind::Ldap,
                source_id: None,
                active: true,
            },
            SourcedMembership {
                group_id: oidc_group,
                group_name: "finance".into(),
                source_kind: MembershipSourceKind::Oidc,
                source_id: None,
                active: true,
            },
            SourcedMembership {
                group_id: local_group,
                group_name: "vpn-admin".into(),
                source_kind: MembershipSourceKind::Local,
                source_id: None,
                active: true,
            },
        ];

        let groups = effective_groups(&[identity(IdentityKind::Ldap, true)], &memberships);
        assert!(groups.contains_key(&ldap_group));
        assert!(groups.contains_key(&local_group));
        assert!(!groups.contains_key(&oidc_group));
    }

    #[test]
    fn normalization_is_case_insensitive() {
        assert_eq!(
            normalize_email(" Person@Example.COM ").unwrap(),
            "person@example.com"
        );
        assert_eq!(
            normalize_group_name(" Engineering ").unwrap(),
            "engineering"
        );
    }
}
