################################################################################
# TRIGGER: azure/front-door-origin-failover-enabled
# Policy:  Checks that Front Door origin groups have failover/origin health
#          configuration.
#
# TRIGGER: The origin group intentionally has no health probe configured.
# This mirrors the AWS CloudFront fixture where the failover configuration is
# omitted from an otherwise valid distribution.
################################################################################

resource "azurerm_cdn_frontdoor_profile" "test" {
  name                = "azure-front-door-profile"
  resource_group_name = azurerm_resource_group.test.name
  sku_name            = "Standard_AzureFrontDoor"
}

resource "azurerm_cdn_frontdoor_endpoint" "test" {
  name                     = "azure-front-door-endpoint"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.test.id
}

resource "azurerm_cdn_frontdoor_origin_group" "no_failover" {
  name                     = "no-failover-origin-group"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.test.id

  load_balancing {
    additional_latency_in_milliseconds = 0
    sample_size                        = 4
    successful_samples_required        = 3
  }

  # health_probe intentionally omitted
}

resource "azurerm_cdn_frontdoor_origin" "primary" {
  name                           = "primary"
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.no_failover.id
  host_name                      = "example.com"
  origin_host_header             = "example.com"
  certificate_name_check_enabled = true
}

resource "azurerm_cdn_frontdoor_route" "test" {
  name                          = "default-route"
  cdn_frontdoor_endpoint_id     = azurerm_cdn_frontdoor_endpoint.test.id
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.no_failover.id
  cdn_frontdoor_origin_ids      = [azurerm_cdn_frontdoor_origin.primary.id]
  supported_protocols           = ["Http", "Https"]
  patterns_to_match             = ["/*"]
  forwarding_protocol           = "HttpsOnly"
  link_to_default_domain        = true
}
