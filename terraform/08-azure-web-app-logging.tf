################################################################################
# TRIGGER: azure/web-app-logging-enabled
# Policy:  Checks that App Service applications have application and HTTP
#          logging configured.
#
# TRIGGER: The optional logs block is intentionally omitted.
################################################################################

resource "azurerm_service_plan" "web_app" {
  name                = "azure-web-app-plan"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  os_type             = "Linux"
  sku_name            = "B1"
}

resource "azurerm_linux_web_app" "no_logging" {
  name                = "azure-web-app-no-logging"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  service_plan_id     = azurerm_service_plan.web_app.id

  site_config {}

  # logs intentionally omitted
}
