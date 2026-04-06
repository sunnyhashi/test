terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
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
