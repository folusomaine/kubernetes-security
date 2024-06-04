package main

deny[msg] {
  input.kind == "Deployment"
  not input.spec.template.spec.securityContext.runAsNonRoot

  msg := "Containers securityContext must include runAsNonRoot"
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.runAsUser == 0

  msg := "Containers must not run as root user (runAsUser: 0)"
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not startswith(container.image, "demo")

  msg := sprintf("Container image '%s' comes from untrusted registry", container.image)
}