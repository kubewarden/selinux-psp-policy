use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{cmp::PartialEq, convert::TryFrom};

use k8s_openapi::api::core::v1 as apicore;

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SELinuxOptionsExternal {
    user: Option<String>,
    role: Option<String>,
    #[serde(rename = "type")]
    type_: Option<String>,
    level: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub(crate) struct SELinuxOptions {
    pub(crate) user: Option<String>,
    pub(crate) role: Option<String>,
    pub(crate) type_: Option<String>,
    pub(crate) level: Option<SELinuxLevel>,
}

impl TryFrom<&SELinuxOptionsExternal> for SELinuxOptions {
    type Error = anyhow::Error;
    fn try_from(selinux_options_external: &SELinuxOptionsExternal) -> Result<SELinuxOptions> {
        let level = if let Some(ref level) = selinux_options_external.level {
            Some(SELinuxLevel::new(level.clone())?)
        } else {
            None
        };
        Ok(SELinuxOptions {
            user: selinux_options_external.user.clone(),
            role: selinux_options_external.role.clone(),
            type_: selinux_options_external.type_.clone(),
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
}

impl PartialEq for SELinuxLevel {
    fn eq(&self, selinux_level: &SELinuxLevel) -> bool {
        if self.level == selinux_level.level {
            return true;
        }
        self.sensitivity == selinux_level.sensitivity && self.categories == selinux_level.categories
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
        let mut splitted_categories: Vec<String> = categories
            .split(',')
            .into_iter()
            .map(String::from)
            .collect();
        splitted_categories.sort();
        Ok(SELinuxLevel {
            level: level.clone(),
            sensitivity: sensitivity.to_string(),
            categories: splitted_categories,
        })
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(tag = "rule")]
pub(crate) enum Rule {
    MustRunAs(SELinuxOptions),
    RunAsAny,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(default)]
pub(crate) struct Settings {
    #[serde(flatten)]
    pub rule: Rule,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            rule: Rule::RunAsAny,
        }
    }
}

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        Ok(())
    }
}
