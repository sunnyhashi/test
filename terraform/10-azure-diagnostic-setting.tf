################################################################################
# TRIGGER: azure/resource-diagnostic-logging-enabled
# Policy:  Checks that Azure resources send diagnostic logs and metrics to a
#          monitoring destination.
#
# TRIGGER: enabled_log is intentionally omitted and the only metric is
# disabled. This is the Azure equivalent of the AWS VPN logging fixture.
################################################################################

resource "azurerm_monitor_diagnostic_setting" "no_logging" {
  name                       = "no-logging"
  target_resource_id         = azurerm_resource_group.test.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.test.id

  metric {
    category = "AllMetrics"
    enabled  = false
  }

  # enabled_log intentionally omitted; the metric is disabled
}

resource "azurerm_log_analytics_workspace" "test" {
  name                = "azure-test-workspace"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}
