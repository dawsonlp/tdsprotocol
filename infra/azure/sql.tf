# Azure SQL: federated logins (Entra ID tokens), routing (connection policy Redirect), the Azure-only login features,
# and Always Encrypted with a VBS enclave.

resource "azurerm_mssql_server" "tds" {
  name                          = "sql-tds-${random_string.suffix.result}-${var.sql_location}" # its own name: a failed attempt can hold one
  resource_group_name           = azurerm_resource_group.tds.name
  location                      = var.sql_location
  version                       = "12.0"
  administrator_login           = "tdsadmin"
  administrator_login_password  = random_password.sql_admin.result
  connection_policy             = "Redirect" # every connection is routed to its database's node, from outside Azure too
  minimum_tls_version           = "1.2"
  public_network_access_enabled = true

  azuread_administrator {
    login_username = var.admin_login
    object_id      = data.azurerm_client_config.current.object_id
  }
}

resource "azurerm_mssql_firewall_rule" "developer" {
  name             = "developer"
  server_id        = azurerm_mssql_server.tds.id
  start_ip_address = var.client_ip
  end_ip_address   = var.client_ip
}

resource "azurerm_mssql_database" "tds" {
  name                        = "tds"
  server_id                   = azurerm_mssql_server.tds.id
  sku_name                    = "GP_S_Gen5_1" # serverless: billed while in use, paused after an hour idle
  min_capacity                = 0.5
  auto_pause_delay_in_minutes = 60
  max_size_gb                 = 2
  enclave_type                = "VBS" # Always Encrypted with secure enclaves (M18)
  storage_account_type        = "Local"
}
