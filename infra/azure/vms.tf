# The VMs. Each shuts down at 05:00 UTC; configure.sh sets them up inside (the domain, SQL Server, the runner):
# SQL Server's logins, port and Browser are set there too, rather than through the SQL IaaS extension, whose resource
# provider would have to be registered on the whole subscription.

resource "azurerm_windows_virtual_machine" "dc" { # the Active Directory domain controller, for Kerberos
  name                  = "vm-tds-dc"
  computer_name         = "tdsdc"
  resource_group_name   = azurerm_resource_group.tds.name
  location              = azurerm_resource_group.tds.location
  size                  = "Standard_B2s"
  admin_username        = "tdsadmin"
  admin_password        = random_password.windows_admin.result
  network_interface_ids = [azurerm_network_interface.dc.id]
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }
  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-core-g2"
    version   = "latest"
  }
}

resource "azurerm_windows_virtual_machine" "sql" { # SQL Server 2022 Developer on Windows: NTLM, Kerberos, the Browser
  name                  = "vm-tds-sql"
  computer_name         = "tdssql"
  resource_group_name   = azurerm_resource_group.tds.name
  location              = azurerm_resource_group.tds.location
  size                  = "Standard_B2ms"
  admin_username        = "tdsadmin"
  admin_password        = random_password.windows_admin.result
  network_interface_ids = [azurerm_network_interface.sql.id]
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }
  source_image_reference {
    publisher = "MicrosoftSQLServer"
    offer     = "sql2022-ws2022"
    sku       = "sqldev-gen2"
    version   = "latest"
  }
}

resource "tls_private_key" "runner" {
  algorithm = "ED25519"
}

resource "azurerm_linux_virtual_machine" "runner" { # where the Kerberos tests run, inside the domain's network
  name                  = "vm-tds-runner"
  computer_name         = "tdsrunner"
  resource_group_name   = azurerm_resource_group.tds.name
  location              = azurerm_resource_group.tds.location
  size                  = "Standard_B1ms"
  admin_username        = "tds"
  network_interface_ids = [azurerm_network_interface.runner.id]
  admin_ssh_key {
    username   = "tds"
    public_key = tls_private_key.runner.public_key_openssh
  }
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }
  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }
}

resource "azurerm_dev_test_global_vm_shutdown_schedule" "nightly" {
  for_each = {
    dc     = azurerm_windows_virtual_machine.dc.id
    sql    = azurerm_windows_virtual_machine.sql.id
    runner = azurerm_linux_virtual_machine.runner.id
  }
  virtual_machine_id    = each.value
  location              = azurerm_resource_group.tds.location
  enabled               = true
  daily_recurrence_time = "0500"
  timezone              = "UTC"
  notification_settings {
    enabled = false
  }
}
