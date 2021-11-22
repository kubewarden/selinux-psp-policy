# Kubewarden policy psp-selinux

## Description

Replacement for the Kubernetes Pod Security Policy that controls the usage of SELinux in the pod
security context and on containers, init containers and ephemeral containers. This policy will
inspect the `.spec.securityContext.seLinuxOptions` of the pod  if the container has no specific
`.spec.securityContext.seLinuxOptions`. In other words, the `seLinuxOptions` of the container, init
container and ephemeral containers take precendence over the pod `seLinuxOptions`, if any.

## Settings

This policy works by defining what `seLinuxOptions` can be set at the pod level and at the container
level.

One of the following setting keys are accepted for this policy:

* `MustRunAs`: contains the desired value for the `seLinuxOptions` parameter. If the pod does not
  contain a `.securityContext`, or a `.securityContext.seLinuxOptions`, then this policy acts as
  mutating and defaults the `seLinuxOptions` attribute to the one provided in the configuration. In
  all cases, pod containers, init container and ephemeral containers `.seLinuxOptions` are checked
  for compatibility if they override the Pod Security Context `seLinuxOptions` value.
* `RunAsAny`: always accepts the request.

Configuration examples:

```yaml
rule: RunAsAny
```

```yaml
rule: MustRunAs
user: user
role: role
type: type
level: s0:c0,c6
```

## License

```
Copyright (C) 2021 Rafael Fernández López <rfernandezlopez@suse.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
