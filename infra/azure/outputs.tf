# What the tests need. Secrets are marked sensitive: configure.sh writes them to a local file, never to the terminal.

output "resource_group" { value = azurerm_resource_group.tds.name }
output "azure_sql_server" { value = azurerm_mssql_server.tds.fully_qualified_domain_name }
output "azure_sql_database" { value = azurerm_mssql_database.tds.name }
output "key_vault_key_id" { value = azurerm_key_vault_key.cmk.versionless_id }
output "sql_vm_public_ip" { value = azurerm_public_ip.sql.ip_address }
output "runner_public_ip" { value = azurerm_public_ip.runner.ip_address }
output "domain" { value = var.domain }

output "secrets" {
  sensitive = true
  value = {
    sql_admin_password     = random_password.sql_admin.result
    windows_admin_password = random_password.windows_admin.result
    test_user_password     = random_password.test_user.result
    runner_ssh_key         = tls_private_key.runner.private_key_openssh
  }
}
