terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

variable "resource_group_name" {
  type    = string
  default = "test-rg"
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "subscription_id" {
  type    = string
  default = "00000000-0000-0000-0000-000000000000"
}

resource "azurerm_storage_account" "test" {
  name                            = "teststorage12345"
  resource_group_name             = var.resource_group_name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = "GRS"
  https_traffic_only_enabled      = false
  min_tls_version                 = "TLS1_0"
  shared_access_key_enabled       = true
  public_network_access_enabled   = true
  default_to_oauth_authentication = false

  blob_properties {
    versioning_enabled = false

    cors_rule {
      allowed_headers    = ["*"]
      allowed_methods    = ["GET", "HEAD"]
      allowed_origins    = ["*"]
      exposed_headers    = ["*"]
      max_age_in_seconds = 0
    }
  }

  tags = {
    environment = "test"
    purpose     = "tfpolicy-testing"
  }
}

resource "azurerm_network_security_group" "test" {
  name                = "test-nsg"
  location            = var.location
  resource_group_name = var.resource_group_name

  security_rule {
    name                       = "allow-http-internet"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-rdp-internet"
    priority                   = 101
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-udp-internet"
    priority                   = 102
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = "53"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = {
    environment = "test"
    purpose     = "tfpolicy-testing"
  }
}

resource "azurerm_role_assignment" "test_owner1" {
  scope                = "/subscriptions/${var.subscription_id}"
  role_definition_name = "Owner"
  principal_id         = "00000000-0000-0000-0000-000000000001"
}

resource "azurerm_role_assignment" "test_owner2" {
  scope                = "/subscriptions/${var.subscription_id}"
  role_definition_name = "Owner"
  principal_id         = "00000000-0000-0000-0000-000000000002"
}

resource "azurerm_role_assignment" "test_owner3" {
  scope                = "/subscriptions/${var.subscription_id}"
  role_definition_name = "Owner"
  principal_id         = "00000000-0000-0000-0000-000000000003"
}

output "storage_account_id" {
  value       = azurerm_storage_account.test.id
  description = "Storage account resource ID for testing"
}

output "nsg_id" {
  value       = azurerm_network_security_group.test.id
  description = "Network security group resource ID for testing"
}
