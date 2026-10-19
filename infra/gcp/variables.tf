variable "project_id" {
  type = string
  validation {
    condition     = can(regex("^tds-rust-auth-[a-z0-9-]+$", var.project_id))
    error_message = "Only a dedicated tds-rust-auth- project is allowed."
  }
}
variable "region" { default = "us-central1" }
variable "zone" { default = "us-central1-a" }
variable "campaign_id" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,30}$", var.campaign_id))
    error_message = "Use a short lowercase campaign identifier."
  }
}
variable "client_cidr" {
  type = string
  validation {
    condition     = can(cidrnetmask(var.client_cidr)) && endswith(var.client_cidr, "/32")
    error_message = "Developer ingress must be one explicit IPv4 /32."
  }
}
variable "expires_at" {
  type = string
  validation {
    condition     = can(formatdate("YYYY", var.expires_at)) && endswith(var.expires_at, "Z")
    error_message = "Use a canonical UTC RFC3339 safety expiry ending in Z, matching the API."
  }
}
variable "ssh_public_key" {
  type = string
  validation {
    condition     = startswith(var.ssh_public_key, "ssh-ed25519 ") && !strcontains(var.ssh_public_key, "PRIVATE")
    error_message = "Provide an ED25519 public key, never a private key."
  }
}
variable "windows_image" { type = string }
variable "linux_image" { type = string }
variable "enable_windows_runner" { default = false }
variable "prior_cost_upper_bound_usd" {
  type    = number
  default = 0
  validation {
    condition     = var.prior_cost_upper_bound_usd >= 0 && var.prior_cost_upper_bound_usd < 8
    error_message = "The campaign has no remaining test allowance."
  }
}
