use anyhow::{anyhow, Result};
use std::convert::TryInto;

extern crate wapc_guest as guest;
use guest::prelude::*;

use k8s_openapi::api::core::v1 as apicore;

extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{protocol_version_guest, request::ValidationRequest, validate_settings};

mod settings;
use settings::{ExternalSettings, SELinuxLevel, SELinuxOptions, Settings};

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<ExternalSettings>);
    register_function("protocol_version", protocol_version_guest);
}

#[derive(Debug, PartialEq)]
enum PolicyResponse {
    Accept,
    Reject(String),
    Mutate(serde_json::Value),
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<ExternalSettings> = ValidationRequest::new(payload)?;

    // It is safe to unwrap here, because the validate_settings function already made sure that
    // ExternalSettings can be converted to Settings.
    let settings: Settings = validation_request.settings.try_into().unwrap();

    let pod = match serde_json::from_value::<apicore::Pod>(validation_request.request.object) {
        Ok(pod) => pod,
        Err(_) => return kubewarden::accept_request(),
    };

    match do_validate(pod, settings)? {
        PolicyResponse::Accept => kubewarden::accept_request(),
        PolicyResponse::Reject(message) => kubewarden::reject_request(Some(message), None),
        PolicyResponse::Mutate(mutated_object) => kubewarden::mutate_request(mutated_object),
    }
}

fn do_validate(pod: apicore::Pod, settings: settings::Settings) -> Result<PolicyResponse> {
    let pod_spec = pod.spec.ok_or_else(|| anyhow!("invalid pod spec"))?;

    match settings {
        Settings::MustRunAs(expected_selinux_options) => {
            let pod_with_defaulted_selinux_options = apicore::Pod {
                spec: Some(apicore::PodSpec {
                    security_context: Some(apicore::PodSecurityContext {
                        se_linux_options: Some(expected_selinux_options.clone().into()),
                        ..apicore::PodSecurityContext::default()
                    }),
                    ..pod_spec.clone()
                }),
                ..apicore::Pod::default()
            };

            // If the pod has no SELinuxOptions, we default it to the expected value. We still have
            // to check that all containers meet the SELinux requirements set by the configuration
            // because individual containers might override the default PodSecurityContext SELinux
            // options

            let mut has_to_mutate = false;
            let pod_selinux_options = if let Some(pod_security_context) = pod_spec.security_context
            {
                if let Some(selinux_options) = pod_security_context.se_linux_options {
                    selinux_options
                } else {
                    has_to_mutate = true;
                    expected_selinux_options.clone().into()
                }
            } else {
                has_to_mutate = true;
                expected_selinux_options.clone().into()
            };

            let all_compliant_containers = pod_spec.containers.into_iter().all(|container| {
                is_selinux_compliant(
                    &container.security_context,
                    expected_selinux_options.clone(),
                    &pod_selinux_options,
                )
            });

            let all_compliant_init_containers = pod_spec
                .init_containers
                .unwrap_or_else(Vec::new)
                .into_iter()
                .all(|container| {
                    is_selinux_compliant(
                        &container.security_context,
                        expected_selinux_options.clone(),
                        &pod_selinux_options,
                    )
                });

            let all_compliant_ephemeral_containers = pod_spec
                .ephemeral_containers
                .unwrap_or_else(Vec::new)
                .into_iter()
                .all(|container| {
                    is_selinux_compliant(
                        &container.security_context,
                        expected_selinux_options.clone(),
                        &pod_selinux_options,
                    )
                });

            if !all_compliant_containers
                || !all_compliant_init_containers
                || !all_compliant_ephemeral_containers
            {
                return Ok(PolicyResponse::Reject(
                    "SELinux validation failed".to_string(),
                ));
            }

            // Mutating is the last step -- if needed. If we are defaulting the SELinux options of
            // the pod security context, at this point we have to have already confirmed that _all_
            // containers meet the desired SELinux options that we are defaulting to.

            if has_to_mutate {
                return Ok(PolicyResponse::Mutate(serde_json::to_value(
                    pod_with_defaulted_selinux_options,
                )?));
            }

            Ok(PolicyResponse::Accept)
        }
        Settings::RunAsAny => Ok(PolicyResponse::Accept),
    }
}

fn is_selinux_compliant(
    security_context: &Option<apicore::SecurityContext>,
    expected_selinux_options: SELinuxOptions,
    pod_selinux_options: &apicore::SELinuxOptions,
) -> bool {
    let selinux_options = match security_context {
        Some(security_context) => security_context
            .se_linux_options
            .clone()
            .unwrap_or_else(|| pod_selinux_options.clone()),
        None => pod_selinux_options.clone(),
    };

    if let Some(level) = selinux_options.level {
        if let Ok(level) = SELinuxLevel::new(level) {
            SELinuxOptions {
                user: selinux_options.user,
                role: selinux_options.role,
                type_: selinux_options.type_,
                level: Some(level),
            } == expected_selinux_options
        } else {
            false
        }
    } else {
        false
    }
}

#[cfg(test)]

mod tests {
    use super::*;

    #[test]
    fn run_as_any_always_accepts() -> Result<()> {
        assert_eq!(
            do_validate(
                apicore::Pod {
                    spec: Some(apicore::PodSpec::default()),
                    ..apicore::Pod::default()
                },
                Settings::RunAsAny,
            )?,
            PolicyResponse::Accept
        );

        Ok(())
    }

    #[test]
    fn must_run_as_rejects_with_invalid_role_user_or_type_in_containers() -> Result<()> {
        let selinux_options = SELinuxOptions {
            user: Some("user".to_string()),
            role: Some("role".to_string()),
            level: Some(SELinuxLevel::new("s0:c0,c6".to_string()).unwrap()),
            type_: Some("type".to_string()),
        };

        // Bad role
        assert_eq!(
            do_validate(
                apicore::Pod {
                    spec: Some({
                        apicore::PodSpec {
                            containers: vec![apicore::Container::default()],
                            security_context: Some(apicore::PodSecurityContext {
                                se_linux_options: Some(selinux_options.clone().into()),
                                ..apicore::PodSecurityContext::default()
                            }),
                            ..apicore::PodSpec::default()
                        }
                    }),
                    ..apicore::Pod::default()
                },
                Settings::MustRunAs(SELinuxOptions {
                    role: Some("invalid".to_string()),
                    ..selinux_options.clone()
                }),
            )?,
            PolicyResponse::Reject("SELinux validation failed".to_string())
        );

        // Bad user
        assert_eq!(
            do_validate(
                apicore::Pod {
                    spec: Some({
                        apicore::PodSpec {
                            containers: vec![apicore::Container::default()],
                            security_context: Some(apicore::PodSecurityContext {
                                se_linux_options: Some(selinux_options.clone().into()),
                                ..apicore::PodSecurityContext::default()
                            }),
                            ..apicore::PodSpec::default()
                        }
                    }),
                    ..apicore::Pod::default()
                },
                Settings::MustRunAs(SELinuxOptions {
                    user: Some("invalid".to_string()),
                    ..selinux_options.clone()
                }),
            )?,
            PolicyResponse::Reject("SELinux validation failed".to_string())
        );

        // Bad type
        assert_eq!(
            do_validate(
                apicore::Pod {
                    spec: Some({
                        apicore::PodSpec {
                            containers: vec![apicore::Container::default()],
                            security_context: Some(apicore::PodSecurityContext {
                                se_linux_options: Some(selinux_options.clone().into()),
                                ..apicore::PodSecurityContext::default()
                            }),
                            ..apicore::PodSpec::default()
                        }
                    }),
                    ..apicore::Pod::default()
                },
                Settings::MustRunAs(SELinuxOptions {
                    type_: Some("invalid".to_string()),
                    ..selinux_options.clone()
                }),
            )?,
            PolicyResponse::Reject("SELinux validation failed".to_string())
        );

        Ok(())
    }

    #[test]
    fn must_run_as_rejects_with_invalid_role_user_or_type_in_init_containers() -> Result<()> {
        let selinux_options = SELinuxOptions {
            user: Some("user".to_string()),
            role: Some("role".to_string()),
            level: Some(SELinuxLevel::new("s0:c0,c6".to_string()).unwrap()),
            type_: Some("type".to_string()),
        };

        // Bad role
        assert_eq!(
            do_validate(
                apicore::Pod {
                    spec: Some({
                        apicore::PodSpec {
                            init_containers: Some(vec![apicore::Container::default()]),
                            security_context: Some(apicore::PodSecurityContext {
                                se_linux_options: Some(selinux_options.clone().into()),
                                ..apicore::PodSecurityContext::default()
                            }),
                            ..apicore::PodSpec::default()
                        }
                    }),
                    ..apicore::Pod::default()
                },
                Settings::MustRunAs(SELinuxOptions {
                    role: Some("invalid".to_string()),
                    ..selinux_options.clone()
                }),
            )?,
            PolicyResponse::Reject("SELinux validation failed".to_string())
        );

        // Bad user
        assert_eq!(
            do_validate(
                apicore::Pod {
                    spec: Some({
                        apicore::PodSpec {
                            init_containers: Some(vec![apicore::Container::default()]),
                            security_context: Some(apicore::PodSecurityContext {
                                se_linux_options: Some(selinux_options.clone().into()),
                                ..apicore::PodSecurityContext::default()
                            }),
                            ..apicore::PodSpec::default()
                        }
                    }),
                    ..apicore::Pod::default()
                },
                Settings::MustRunAs(SELinuxOptions {
                    user: Some("invalid".to_string()),
                    ..selinux_options.clone()
                }),
            )?,
            PolicyResponse::Reject("SELinux validation failed".to_string())
        );

        // Bad type
        assert_eq!(
            do_validate(
                apicore::Pod {
                    spec: Some({
                        apicore::PodSpec {
                            init_containers: Some(vec![apicore::Container::default()]),
                            security_context: Some(apicore::PodSecurityContext {
                                se_linux_options: Some(selinux_options.clone().into()),
                                ..apicore::PodSecurityContext::default()
                            }),
                            ..apicore::PodSpec::default()
                        }
                    }),
                    ..apicore::Pod::default()
                },
                Settings::MustRunAs(SELinuxOptions {
                    type_: Some("invalid".to_string()),
                    ..selinux_options.clone()
                }),
            )?,
            PolicyResponse::Reject("SELinux validation failed".to_string())
        );

        Ok(())
    }

    #[test]
    fn must_run_as_rejects_with_invalid_role_user_or_type_in_ephemeral_containers() -> Result<()> {
        let selinux_options = SELinuxOptions {
            user: Some("user".to_string()),
            role: Some("role".to_string()),
            level: Some(SELinuxLevel::new("s0:c0,c6".to_string()).unwrap()),
            type_: Some("type".to_string()),
        };

        // Bad role
        assert_eq!(
            do_validate(
                apicore::Pod {
                    spec: Some({
                        apicore::PodSpec {
                            ephemeral_containers: Some(
                                vec![apicore::EphemeralContainer::default()],
                            ),
                            security_context: Some(apicore::PodSecurityContext {
                                se_linux_options: Some(selinux_options.clone().into()),
                                ..apicore::PodSecurityContext::default()
                            }),
                            ..apicore::PodSpec::default()
                        }
                    }),
                    ..apicore::Pod::default()
                },
                Settings::MustRunAs(SELinuxOptions {
                    role: Some("invalid".to_string()),
                    ..selinux_options.clone()
                }),
            )?,
            PolicyResponse::Reject("SELinux validation failed".to_string())
        );

        // Bad user
        assert_eq!(
            do_validate(
                apicore::Pod {
                    spec: Some({
                        apicore::PodSpec {
                            ephemeral_containers: Some(
                                vec![apicore::EphemeralContainer::default()],
                            ),
                            security_context: Some(apicore::PodSecurityContext {
                                se_linux_options: Some(selinux_options.clone().into()),
                                ..apicore::PodSecurityContext::default()
                            }),
                            ..apicore::PodSpec::default()
                        }
                    }),
                    ..apicore::Pod::default()
                },
                Settings::MustRunAs(SELinuxOptions {
                    user: Some("invalid".to_string()),
                    ..selinux_options.clone()
                }),
            )?,
            PolicyResponse::Reject("SELinux validation failed".to_string())
        );

        // Bad type
        assert_eq!(
            do_validate(
                apicore::Pod {
                    spec: Some({
                        apicore::PodSpec {
                            ephemeral_containers: Some(
                                vec![apicore::EphemeralContainer::default()],
                            ),
                            security_context: Some(apicore::PodSecurityContext {
                                se_linux_options: Some(selinux_options.clone().into()),
                                ..apicore::PodSecurityContext::default()
                            }),
                            ..apicore::PodSpec::default()
                        }
                    }),
                    ..apicore::Pod::default()
                },
                Settings::MustRunAs(SELinuxOptions {
                    type_: Some("invalid".to_string()),
                    ..selinux_options.clone()
                }),
            )?,
            PolicyResponse::Reject("SELinux validation failed".to_string())
        );

        Ok(())
    }

    #[test]
    fn must_run_as_rejects_unequal_levels() -> Result<()> {
        let selinux_options = SELinuxOptions {
            user: Some("user".to_string()),
            role: Some("role".to_string()),
            level: Some(SELinuxLevel::new("s0".to_string())?),
            type_: Some("type".to_string()),
        };

        // Bad level
        assert_eq!(
            do_validate(
                apicore::Pod {
                    spec: Some({
                        apicore::PodSpec {
                            containers: vec![apicore::Container::default()],
                            security_context: Some(apicore::PodSecurityContext {
                                se_linux_options: Some(selinux_options.clone().into()),
                                ..apicore::PodSecurityContext::default()
                            }),
                            ..apicore::PodSpec::default()
                        }
                    }),
                    ..apicore::Pod::default()
                },
                Settings::MustRunAs(SELinuxOptions {
                    level: Some(SELinuxLevel::new("s0:c1,c2".to_string())?),
                    ..selinux_options.clone()
                }),
            )?,
            PolicyResponse::Reject("SELinux validation failed".to_string())
        );

        Ok(())
    }

    #[test]
    fn must_run_as_rejects_unequal_sensitivity() -> Result<()> {
        let selinux_options = SELinuxOptions {
            user: Some("user".to_string()),
            role: Some("role".to_string()),
            level: Some(SELinuxLevel::new("s1:c6".to_string())?),
            type_: Some("type".to_string()),
        };

        // Unmatching sensitivity
        assert_eq!(
            do_validate(
                apicore::Pod {
                    spec: Some({
                        apicore::PodSpec {
                            containers: vec![apicore::Container::default()],
                            security_context: Some(apicore::PodSecurityContext {
                                se_linux_options: Some(selinux_options.clone().into()),
                                ..apicore::PodSecurityContext::default()
                            }),
                            ..apicore::PodSpec::default()
                        }
                    }),
                    ..apicore::Pod::default()
                },
                Settings::MustRunAs(SELinuxOptions {
                    level: Some(SELinuxLevel::new("s0:c6".to_string())?),
                    ..selinux_options.clone()
                }),
            )?,
            PolicyResponse::Reject("SELinux validation failed".to_string())
        );

        Ok(())
    }

    #[test]
    fn must_run_as_rejects_unequal_categories() -> Result<()> {
        let selinux_options = SELinuxOptions {
            user: Some("user".to_string()),
            role: Some("role".to_string()),
            level: Some(SELinuxLevel::new("s0:c1,c7".to_string())?),
            type_: Some("type".to_string()),
        };

        // Unmatching categories
        assert_eq!(
            do_validate(
                apicore::Pod {
                    spec: Some({
                        apicore::PodSpec {
                            containers: vec![apicore::Container::default()],
                            security_context: Some(apicore::PodSecurityContext {
                                se_linux_options: Some(selinux_options.clone().into()),
                                ..apicore::PodSecurityContext::default()
                            }),
                            ..apicore::PodSpec::default()
                        }
                    }),
                    ..apicore::Pod::default()
                },
                Settings::MustRunAs(SELinuxOptions {
                    level: Some(SELinuxLevel::new("s0:c0,c8".to_string())?),
                    ..selinux_options.clone()
                }),
            )?,
            PolicyResponse::Reject("SELinux validation failed".to_string())
        );

        Ok(())
    }

    #[test]
    fn must_run_as_accepts_matching() -> Result<()> {
        let selinux_options = SELinuxOptions {
            user: Some("user".to_string()),
            role: Some("role".to_string()),
            level: Some(SELinuxLevel::new("s0:c1,c7".to_string())?),
            type_: Some("type".to_string()),
        };

        // Matching rule
        assert_eq!(
            do_validate(
                apicore::Pod {
                    spec: Some({
                        apicore::PodSpec {
                            containers: vec![apicore::Container::default()],
                            security_context: Some(apicore::PodSecurityContext {
                                se_linux_options: Some(selinux_options.clone().into()),
                                ..apicore::PodSecurityContext::default()
                            }),
                            ..apicore::PodSpec::default()
                        }
                    }),
                    ..apicore::Pod::default()
                },
                Settings::MustRunAs(SELinuxOptions {
                    level: Some(SELinuxLevel::new("s0:c1,c7".to_string())?),
                    ..selinux_options.clone()
                }),
            )?,
            PolicyResponse::Accept
        );

        Ok(())
    }

    #[test]
    fn must_run_as_accepts_matching_unordered_categories() -> Result<()> {
        let selinux_options = SELinuxOptions {
            user: Some("user".to_string()),
            role: Some("role".to_string()),
            level: Some(SELinuxLevel::new("s0:c1,c7".to_string())?),
            type_: Some("type".to_string()),
        };

        // Matching rule with different category order
        assert_eq!(
            do_validate(
                apicore::Pod {
                    spec: Some({
                        apicore::PodSpec {
                            containers: vec![apicore::Container::default()],
                            security_context: Some(apicore::PodSecurityContext {
                                se_linux_options: Some(selinux_options.clone().into()),
                                ..apicore::PodSecurityContext::default()
                            }),
                            ..apicore::PodSpec::default()
                        }
                    }),
                    ..apicore::Pod::default()
                },
                Settings::MustRunAs(SELinuxOptions {
                    level: Some(SELinuxLevel::new("s0:c7,c1".to_string())?),
                    ..selinux_options.clone()
                }),
            )?,
            PolicyResponse::Accept
        );

        Ok(())
    }

    #[test]
    fn must_run_as_mutates_with_empty_pod_security_context() -> Result<()> {
        let selinux_options = SELinuxOptions {
            user: Some("user".to_string()),
            role: Some("role".to_string()),
            level: Some(SELinuxLevel::new("s0:c1,c7".to_string())?),
            type_: Some("type".to_string()),
        };

        assert_eq!(
            do_validate(
                apicore::Pod {
                    spec: Some({
                        apicore::PodSpec {
                            containers: vec![apicore::Container::default()],
                            security_context: None,
                            ..apicore::PodSpec::default()
                        }
                    }),
                    ..apicore::Pod::default()
                },
                Settings::MustRunAs(SELinuxOptions {
                    level: Some(SELinuxLevel::new("s0:c7,c1".to_string())?),
                    ..selinux_options.clone()
                }),
            )?,
            PolicyResponse::Mutate(serde_json::to_value(apicore::Pod {
                spec: Some(apicore::PodSpec {
                    containers: vec![apicore::Container::default()],
                    security_context: Some(apicore::PodSecurityContext {
                        se_linux_options: Some(apicore::SELinuxOptions {
                            user: Some("user".to_string()),
                            role: Some("role".to_string()),
                            level: Some("s0:c7,c1".to_string()),
                            type_: Some("type".to_string()),
                        }),
                        ..apicore::PodSecurityContext::default()
                    }),
                    ..apicore::PodSpec::default()
                }),
                ..apicore::Pod::default()
            })?)
        );

        Ok(())
    }

    #[test]
    fn must_run_as_mutates_with_empty_selinux_options() -> Result<()> {
        let selinux_options = SELinuxOptions {
            user: Some("user".to_string()),
            role: Some("role".to_string()),
            level: Some(SELinuxLevel::new("s0:c1,c7".to_string())?),
            type_: Some("type".to_string()),
        };

        assert_eq!(
            do_validate(
                apicore::Pod {
                    spec: Some({
                        apicore::PodSpec {
                            containers: vec![apicore::Container::default()],
                            security_context: Some(apicore::PodSecurityContext {
                                se_linux_options: None,
                                ..apicore::PodSecurityContext::default()
                            }),
                            ..apicore::PodSpec::default()
                        }
                    }),
                    ..apicore::Pod::default()
                },
                Settings::MustRunAs(SELinuxOptions {
                    level: Some(SELinuxLevel::new("s0:c7,c1".to_string())?),
                    ..selinux_options.clone()
                }),
            )?,
            PolicyResponse::Mutate(serde_json::to_value(apicore::Pod {
                spec: Some(apicore::PodSpec {
                    containers: vec![apicore::Container::default()],
                    security_context: Some(apicore::PodSecurityContext {
                        se_linux_options: Some(apicore::SELinuxOptions {
                            user: Some("user".to_string()),
                            role: Some("role".to_string()),
                            level: Some("s0:c7,c1".to_string()),
                            type_: Some("type".to_string()),
                        }),
                        ..apicore::PodSecurityContext::default()
                    }),
                    ..apicore::PodSpec::default()
                }),
                ..apicore::Pod::default()
            })?)
        );

        Ok(())
    }

    #[test]
    fn must_run_as_rejects_with_empty_selinux_options_and_unmatching_existing_container(
    ) -> Result<()> {
        let selinux_options = SELinuxOptions {
            user: Some("user".to_string()),
            role: Some("role".to_string()),
            level: Some(SELinuxLevel::new("s0:c1,c7".to_string())?),
            type_: Some("type".to_string()),
        };

        assert_eq!(
            do_validate(
                apicore::Pod {
                    spec: Some({
                        apicore::PodSpec {
                            containers: vec![apicore::Container {
                                security_context: Some(apicore::SecurityContext {
                                    se_linux_options: Some(apicore::SELinuxOptions {
                                        level: Some("s0:c2".to_string()),
                                        ..selinux_options.clone().into()
                                    }),
                                    ..apicore::SecurityContext::default()
                                }),
                                ..apicore::Container::default()
                            }],
                            security_context: Some(apicore::PodSecurityContext {
                                se_linux_options: None,
                                ..apicore::PodSecurityContext::default()
                            }),
                            ..apicore::PodSpec::default()
                        }
                    }),
                    ..apicore::Pod::default()
                },
                Settings::MustRunAs(SELinuxOptions {
                    level: Some(SELinuxLevel::new("s0:c7,c1".to_string())?),
                    ..selinux_options.clone()
                }),
            )?,
            PolicyResponse::Reject("SELinux validation failed".to_string())
        );

        Ok(())
    }
}
