# The campaign's non-user Entra identities: a service principal (a dedicated app registration whose secret expires
# with the resource group) and the runner VM's system-assigned managed identity (vms.tf). Each may use the Key Vault
# key; configure.py makes each a database user, signed in as the Entra admin.

data "azuread_client_config" "current" {}

resource "azuread_application" "campaign" {
  display_name = "tds-rust-azure-${random_string.suffix.result}"
  owners       = [data.azuread_client_config.current.object_id]
}

resource "azuread_service_principal" "campaign" {
  client_id = azuread_application.campaign.client_id
  owners    = [data.azuread_client_config.current.object_id]
}

resource "azuread_application_password" "campaign" {
  application_id = azuread_application.campaign.id
  display_name   = "tds campaign"
  end_date       = local.deadline # unusable after the deadline, even if this registration were left behind
}

resource "azurerm_role_assignment" "service_principal_keys" {
  scope                = azurerm_key_vault.tds.id
  role_definition_name = "Key Vault Crypto User"
  principal_id         = azuread_service_principal.campaign.object_id
}

resource "azurerm_role_assignment" "runner_keys" {
  scope                = azurerm_key_vault.tds.id
  role_definition_name = "Key Vault Crypto User"
  principal_id         = azurerm_linux_virtual_machine.runner.identity[0].principal_id
}
