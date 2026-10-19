terraform {
  required_version = ">= 1.5.7"
  required_providers {
    google = { source = "hashicorp/google", version = "= 7.18.0" }
  }
}

provider "google" {
  billing_project       = var.project_id
  user_project_override = var.bootstrap_complete
}

provider "google" {
  alias = "bootstrap"
}

variable "project_id" {
  type = string
  validation {
    condition     = can(regex("^tds-rust-auth-[a-z0-9-]+$", var.project_id))
    error_message = "Use a dedicated tds-rust-auth- project ID."
  }
}

variable "billing_account" {
  type     = string
  default  = null
  nullable = true
}

variable "bootstrap_complete" {
  description = "False for project/API bootstrap; true before linking billing using the new project's API consumer."
  type        = bool
  default     = false
}

variable "auto_create_network" {
  description = "True for initial unbilled project creation; the separate defaults root removes GCP's default network afterward."
  type        = bool
  default     = true
}

variable "organization_id" {
  type     = string
  default  = null
  nullable = true
}

resource "google_project" "lab" {
  name                = "TDS Rust authentication lab"
  project_id          = var.project_id
  org_id              = var.organization_id
  billing_account     = var.billing_account
  auto_create_network = var.auto_create_network
  deletion_policy     = "DELETE"
  labels = {
    purpose   = "tds-rust-auth"
    temporary = "true"
  }
}

# Bootstrap billing lookup without enabling services in unrelated projects.
resource "google_project_service" "billing" {
  provider           = google.bootstrap
  project            = var.project_id
  service            = "cloudbilling.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "resource_manager" {
  provider           = google.bootstrap
  project            = var.project_id
  service            = "cloudresourcemanager.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "compute" {
  provider           = google.bootstrap
  project            = google_project.lab.project_id
  service            = "compute.googleapis.com"
  disable_on_destroy = false
  depends_on         = [google_project_service.resource_manager]
}

resource "google_project_service" "service_usage" {
  provider           = google.bootstrap
  project            = var.project_id
  service            = "serviceusage.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "iam" {
  provider           = google.bootstrap
  project            = var.project_id
  service            = "iam.googleapis.com"
  disable_on_destroy = false
}

output "project_id" { value = google_project.lab.project_id }
output "project_number" { value = google_project.lab.number }
