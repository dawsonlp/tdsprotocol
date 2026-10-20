data "azurerm_client_config" "current" {}

resource "random_string" "suffix" { # globally unique names for the SQL server and the Key Vault
  length  = 6
  upper   = false
  special = false
}

resource "random_password" "sql_admin" { # Azure SQL's SQL login, for setting databases up
  length           = 24
  override_special = "!#%*-_=+"
}

resource "random_password" "windows_admin" { # the Windows VMs' local admin, and the domain's administrator
  length           = 24
  override_special = "!#%*-_=+"
}

resource "random_password" "test_user" { # the domain user the Windows logins test with
  length           = 24
  override_special = "!#%*-_=+"
}

resource "time_static" "created" {} # fixed at the first apply: the lifetime counts from here

locals {
  deadline = timeadd(time_static.created.rfc3339, "${var.lifetime_hours}h") # deletion, and the service principal's secret expiry
}

resource "azurerm_resource_group" "tds" {
  name     = var.resource_group_name
  location = var.location
  tags = {
    purpose   = "tds driver tests (D-62): Rust Azure acceptance"
    temporary = "true: terraform destroy when done"
    expires   = local.deadline # lifetime.tf deletes the group at this time
    owner     = var.admin_login
  }
}
