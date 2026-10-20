# The campaign's limits. A budget alerts at 50, 80 and 100% of the cap; Azure budgets cannot stop spending. The hard
# stop is a Logic App that deletes the whole resource group at the deadline (main.tf), even if terraform destroy never
# runs. It deletes itself with the group. The service principal's app registration is outside the group: its secret
# expires at the same deadline (identities.tf), and terraform destroy removes it.

resource "azurerm_consumption_budget_resource_group" "cap" {
  name              = "budget-tds-campaign"
  resource_group_id = azurerm_resource_group.tds.id
  amount            = var.budget_amount
  time_grain        = "Monthly"

  time_period {
    start_date = formatdate("YYYY-MM-01'T'00:00:00Z", time_static.created.rfc3339) # budgets start on a month's first day
  }

  dynamic "notification" {
    for_each = [50, 80, 100]
    content {
      enabled        = true
      threshold      = notification.value
      operator       = "GreaterThanOrEqualTo"
      threshold_type = "Actual"
      contact_emails = [var.alert_email]
    }
  }
}

resource "azurerm_logic_app_workflow" "expiry" {
  name                = "logic-tds-expiry"
  resource_group_name = azurerm_resource_group.tds.name
  location            = azurerm_resource_group.tds.location
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_role_assignment" "expiry" { # deleting a resource group needs Contributor on it
  scope                = azurerm_resource_group.tds.id
  role_definition_name = "Contributor"
  principal_id         = azurerm_logic_app_workflow.expiry.identity[0].principal_id
}

resource "azurerm_logic_app_trigger_recurrence" "deadline" { # first run at the deadline; nothing is left to run again
  name         = "at-deadline"
  logic_app_id = azurerm_logic_app_workflow.expiry.id
  frequency    = "Day"
  interval     = 1
  start_time   = local.deadline
}

resource "azurerm_logic_app_action_custom" "delete" {
  name         = "delete-resource-group"
  logic_app_id = azurerm_logic_app_workflow.expiry.id
  body = jsonencode({
    type     = "Http"
    runAfter = {}
    inputs = {
      method = "DELETE"
      uri    = "https://management.azure.com${azurerm_resource_group.tds.id}?api-version=2021-04-01"
      authentication = {
        type     = "ManagedServiceIdentity"
        audience = "https://management.azure.com/"
      }
    }
  })
  depends_on = [azurerm_role_assignment.expiry]
}
