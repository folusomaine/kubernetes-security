package main

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]

  not container.securityContext

  msg := "Container is missing securityContext configuration"
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext

  not container.securityContext.runAsNonRoot == true

  msg := "Container securityContext must runAsNonRoot"
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext

  not container.securityContext.allowPrivilegeEscalation == false

  msg := sprintf("Must set container securityContext allowPrivilegeEscalation to false in '%s'", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext

  container.securityContext.runAsUser == 0

  msg := "Containers must not run as root user (runAsUser: 0)"
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not startswith(container.image, "trusted.registry.local/")

  msg := sprintf("Container image '%s' comes from untrusted registry", [container.image])
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext
  
  container.securityContext.privileged == true

  msg := sprintf("Privileged container '%s' is not allowed", [container.name])
}
