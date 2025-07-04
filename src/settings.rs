use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
    cmp::PartialEq,
    collections::HashSet,
    convert::{TryFrom, TryInto},
    iter::FromIterator,
};

use k8s_openapi::api::core::v1 as apicore;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(crate) struct SELinuxOptionsExternal {
    user: Option<String>,
    role: Option<String>,
    #[serde(rename = "type")]
    type_: Option<String>,
    level: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub(crate) struct SELinuxOptions {
    pub(crate) user: Option<String>,
    pub(crate) role: Option<String>,
    pub(crate) type_: Option<String>,
    pub(crate) level: Option<SELinuxLevel>,
}

impl TryFrom<SELinuxOptionsExternal> for SELinuxOptions {
    type Error = anyhow::Error;
    fn try_from(selinux_options_external: SELinuxOptionsExternal) -> Result<SELinuxOptions> {
        let level = if let Some(ref level) = selinux_options_external.level {
            Some(SELinuxLevel::new(level.clone())?)
        } else {
            None
        };
        Ok(SELinuxOptions {
            user: selinux_options_external.user.clone(),
            role: selinux_options_external.role.clone(),
            type_: selinux_options_external.type_,
            level,
        })
    }
}

impl From<SELinuxOptions> for apicore::SELinuxOptions {
    fn from(selinux_options: SELinuxOptions) -> apicore::SELinuxOptions {
        apicore::SELinuxOptions {
            level: selinux_options.level.map(|level| level.level),
            role: selinux_options.role,
            type_: selinux_options.type_,
            user: selinux_options.user,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct SELinuxLevel {
    level: String,
    sensitivity: String,
    categories: Vec<String>,
    categories_hashset: HashSet<String>,
}

impl PartialEq for SELinuxLevel {
    fn eq(&self, selinux_level: &SELinuxLevel) -> bool {
        if self.level == selinux_level.level {
            return true;
        }
        self.sensitivity == selinux_level.sensitivity
            && self.categories_hashset == selinux_level.categories_hashset
    }
}

impl SELinuxLevel {
    pub(crate) fn new(level: String) -> Result<SELinuxLevel> {
        let mut splitted_level = level.split(':');
        if splitted_level.clone().count() != 2 {
            return Ok(SELinuxLevel {
                level,
                ..SELinuxLevel::default()
            });
        }
        let (sensitivity, categories) = (
            splitted_level.next().unwrap(),
            splitted_level.next().unwrap(),
        );
        let splitted_categories: Vec<String> = categories.split(',').map(String::from).collect();
        let categories_hashset = HashSet::from_iter(splitted_categories.clone());
        Ok(SELinuxLevel {
            level: level.clone(),
            sensitivity: sensitivity.to_string(),
            categories: splitted_categories,
            categories_hashset,
        })
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
#[serde(tag = "rule", deny_unknown_fields)]
pub(crate) enum ExternalSettings {
    MustRunAs(SELinuxOptionsExternal),
    #[default]
    RunAsAny,
}

#[derive(Clone, Debug)]
pub(crate) enum Settings {
    MustRunAs(SELinuxOptions),
    RunAsAny,
}

impl TryFrom<ExternalSettings> for Settings {
    type Error = anyhow::Error;
    fn try_from(settings: ExternalSettings) -> Result<Settings> {
        match settings {
            ExternalSettings::MustRunAs(selinux_options) => {
                Ok(Settings::MustRunAs(selinux_options.try_into()?))
            }
            ExternalSettings::RunAsAny => Ok(Settings::RunAsAny),
        }
    }
}

impl kubewarden::settings::Validatable for ExternalSettings {
    fn validate(&self) -> Result<(), String> {
        match self {
            ExternalSettings::RunAsAny => Ok(()),
            ExternalSettings::MustRunAs(selinux_options) => {
                if selinux_options.user.is_none()
                    && selinux_options.role.is_none()
                    && selinux_options.type_.is_none()
                    && selinux_options.level.is_none()
                {
                    return Err(
                        "you have to provide at least a user, group, type or level settings"
                            .to_string(),
                    );
                }
                if let Err(err) = TryInto::<Settings>::try_into(self.clone()) {
                    return Err(format!("settings are invalid: {err}"));
                }
                Ok(())
            }
        }
    }
}
