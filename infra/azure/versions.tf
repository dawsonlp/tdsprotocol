# Azure test infrastructure for the driver's logins and Azure-only features (D-62). Short-lived: torn down after.
terraform {
  required_version = ">= 1.9"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.0" }
    random  = { source = "hashicorp/random", version = "~> 3.6" }
    tls     = { source = "hashicorp/tls", version = "~> 4.0" }
  }
}

provider "azurerm" {
  subscription_id = var.subscription_id
  features {
    key_vault {
      purge_soft_delete_on_destroy = true # torn down means gone: no soft-deleted vault left behind
    }
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}
