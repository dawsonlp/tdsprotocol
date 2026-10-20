# Key Vault: an RSA key as an Always Encrypted master key (M17, D-60).

resource "azurerm_key_vault" "tds" {
  name                       = "kv-tds-${random_string.suffix.result}"
  resource_group_name        = azurerm_resource_group.tds.name
  location                   = azurerm_resource_group.tds.location
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  rbac_authorization_enabled = true
  soft_delete_retention_days = 7
  purge_protection_enabled   = false

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = [var.client_ip, azurerm_public_ip.runner.ip_address]
  }
}

resource "azurerm_role_assignment" "key_officer" {
  scope                = azurerm_key_vault.tds.id
  role_definition_name = "Key Vault Crypto Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_key_vault_key" "cmk" {
  name         = "tds-cmk"
  key_vault_id = azurerm_key_vault.tds.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["wrapKey", "unwrapKey", "sign", "verify"]
  depends_on   = [azurerm_role_assignment.key_officer]
}
