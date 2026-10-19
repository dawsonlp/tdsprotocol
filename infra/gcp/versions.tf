terraform {
  required_version = ">= 1.5.7"
  required_providers {
    google = { source = "hashicorp/google", version = "= 7.18.0" }
  }
}

provider "google" {
  project               = var.project_id
  region                = var.region
  zone                  = var.zone
  billing_project       = var.project_id
  user_project_override = true
}
