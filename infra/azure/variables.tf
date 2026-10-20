variable "subscription_id" {
  description = "The Azure subscription the resource group goes in: az account show --query id -o tsv."
  type        = string
}

variable "location" {
  type    = string
  default = "eastus2"
}

variable "sql_location" {
  description = "Azure SQL's region, which can differ from the rest: Azure can refuse to provision Azure SQL in a region for a subscription (ProvisioningDisabled)."
  type        = string
  default     = "eastus"
}

variable "client_ip" {
  description = "The developer's public address: the only one the network and Azure SQL accept connections from."
  type        = string
}

variable "admin_login" {
  description = "The signed-in user's name (UPN): Azure SQL's Entra admin, so federated logins can be tested as them."
  type        = string
}

variable "domain" {
  description = "The test Active Directory domain."
  type        = string
  default     = "tds.test"
}

variable "resource_group_name" {
  description = "The campaign's one resource group: everything is created in it and deleted with it."
  type        = string
  default     = "rg-tds-rust-azure"
}

variable "lifetime_hours" {
  description = "Hours after creation when the resource group deletes itself, even if terraform destroy never runs."
  type        = number
  default     = 24
}

variable "budget_amount" {
  description = "The campaign's cost cap in the subscription's currency (USD). Azure budgets alert; the timed deletion stops spending."
  type        = number
  default     = 25
}

variable "alert_email" {
  description = "Where budget alerts go."
  type        = string
}
