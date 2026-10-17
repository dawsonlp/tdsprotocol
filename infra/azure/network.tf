# One network: the domain controller, SQL Server on Windows, and the Linux runner the Kerberos tests run from. Only
# the developer's address can reach it: SQL Server's port and the Browser's on the SQL VM, and SSH on the runner.

resource "azurerm_virtual_network" "tds" {
  name                = "vnet-tds"
  resource_group_name = azurerm_resource_group.tds.name
  location            = azurerm_resource_group.tds.location
  address_space       = ["10.42.0.0/16"]
}

resource "azurerm_subnet" "vms" {
  name                 = "vms"
  resource_group_name  = azurerm_resource_group.tds.name
  virtual_network_name = azurerm_virtual_network.tds.name
  address_prefixes     = ["10.42.1.0/24"]
}

resource "azurerm_network_security_group" "vms" {
  name                = "nsg-tds-vms"
  resource_group_name = azurerm_resource_group.tds.name
  location            = azurerm_resource_group.tds.location

  security_rule {
    name                       = "sql-from-developer"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = var.client_ip
    source_port_range          = "*"
    destination_address_prefix = "10.42.1.5"
    destination_port_range     = "1433"
  }
  security_rule {
    name                       = "browser-from-developer"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_address_prefix      = var.client_ip
    source_port_range          = "*"
    destination_address_prefix = "10.42.1.5"
    destination_port_range     = "1434"
  }
  security_rule {
    name                       = "ssh-from-developer"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefix      = var.client_ip
    source_port_range          = "*"
    destination_address_prefix = "10.42.1.6"
    destination_port_range     = "22"
  }
}

resource "azurerm_subnet_network_security_group_association" "vms" {
  subnet_id                 = azurerm_subnet.vms.id
  network_security_group_id = azurerm_network_security_group.vms.id
}

resource "azurerm_public_ip" "sql" {
  name                = "pip-tds-sql"
  resource_group_name = azurerm_resource_group.tds.name
  location            = azurerm_resource_group.tds.location
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_public_ip" "runner" {
  name                = "pip-tds-runner"
  resource_group_name = azurerm_resource_group.tds.name
  location            = azurerm_resource_group.tds.location
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_interface" "dc" {
  name                = "nic-tds-dc"
  resource_group_name = azurerm_resource_group.tds.name
  location            = azurerm_resource_group.tds.location
  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.vms.id
    private_ip_address_allocation = "Static"
    private_ip_address            = "10.42.1.4"
  }
}

resource "azurerm_network_interface" "sql" {
  name                = "nic-tds-sql"
  resource_group_name = azurerm_resource_group.tds.name
  location            = azurerm_resource_group.tds.location
  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.vms.id
    private_ip_address_allocation = "Static"
    private_ip_address            = "10.42.1.5"
    public_ip_address_id          = azurerm_public_ip.sql.id
  }
}

resource "azurerm_network_interface" "runner" {
  name                = "nic-tds-runner"
  resource_group_name = azurerm_resource_group.tds.name
  location            = azurerm_resource_group.tds.location
  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.vms.id
    private_ip_address_allocation = "Static"
    private_ip_address            = "10.42.1.6"
    public_ip_address_id          = azurerm_public_ip.runner.id
  }
}
