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

resource "azurerm_resource_group" "tds" {
  name     = "rg-tds-driver-tests"
  location = var.location
  tags = {
    purpose   = "tds driver tests (D-62)"
    temporary = "true: terraform destroy when done"
    owner     = var.admin_login
  }
}
