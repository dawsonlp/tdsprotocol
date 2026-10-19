# One-time recovery of GCP's automatically created default network. Import these
# existing resources, then destroy this root; never apply it to create a network.
terraform {
  required_version = ">= 1.5.7"
  required_providers {
    google = { source = "hashicorp/google", version = "= 7.18.0" }
  }
}
variable "project_id" {
  type = string
  validation {
    condition     = startswith(var.project_id, "tds-rust-auth-")
    error_message = "Only the new disposable lab project may be cleaned."
  }
}
provider "google" {
  project               = var.project_id
  billing_project       = var.project_id
  user_project_override = true
}
resource "google_compute_network" "default" {
  name                    = "default"
  auto_create_subnetworks = true
}
resource "google_compute_firewall" "default" {
  for_each = toset(["default-allow-icmp", "default-allow-internal", "default-allow-rdp", "default-allow-ssh"])
  name     = each.key
  network  = google_compute_network.default.id
  allow { protocol = "icmp" }
}
