terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "mock_access_key"
  secret_key                  = "mock_secret_key"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  # Required for s3control resources
  default_tags {
    tags = { Environment = "test" }
  }
}

provider "azurerm" {
  features {}

  subscription_id            = var.azure_subscription_id
  skip_provider_registration = true
}

variable "azure_subscription_id" {
  type    = string
  default = "00000000-0000-0000-0000-000000000000"
}

variable "azure_location" {
  type    = string
  default = "eastus"
}

resource "azurerm_resource_group" "test" {
  name     = "azure-resource-test"
  location = var.azure_location
}

variable "key_algorithm" {
  type    = string
  default = "RSA_2048"
}

resource "aws_acm_certificate" "test_cert" {
  domain_name       = "example.com"
  validation_method = "DNS"
  key_algorithm     = var.key_algorithm
}
