# What the tests need. Secrets are marked sensitive: configure.sh writes them to a local file, never to the terminal.

output "resource_group" { value = azurerm_resource_group.tds.name }
output "azure_sql_server" { value = azurerm_mssql_server.tds.fully_qualified_domain_name }
output "azure_sql_database" { value = azurerm_mssql_database.tds.name }
output "key_vault_key_id" { value = azurerm_key_vault_key.cmk.versionless_id }
output "sql_vm_public_ip" { value = azurerm_public_ip.sql.ip_address }
output "runner_public_ip" { value = azurerm_public_ip.runner.ip_address }
output "domain" { value = var.domain }
output "tenant_id" { value = data.azurerm_client_config.current.tenant_id }
output "service_principal_client_id" { value = azuread_application.campaign.client_id }
output "service_principal_name" { value = azuread_application.campaign.display_name }
output "runner_identity_name" { value = azurerm_linux_virtual_machine.runner.name } # its database user's name
output "deadline" { value = local.deadline }

output "secrets" {
  sensitive = true
  value = {
    sql_admin_password       = random_password.sql_admin.result
    windows_admin_password   = random_password.windows_admin.result
    test_user_password       = random_password.test_user.result
    runner_ssh_key           = tls_private_key.runner.private_key_openssh
    service_principal_secret = azuread_application_password.campaign.value
  }
}
