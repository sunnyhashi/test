terraform {
  required_version = ">= 1.5.0"

  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}

variable "policy_test_mode" {
  description = "Set to allow to pass policy, deny to fail policy."
  type        = string
  default     = "deny"

  validation {
    condition     = contains(["allow", "deny"], var.policy_test_mode)
    error_message = "policy_test_mode must be allow or deny."
  }
}

resource "null_resource" "policy_probe" {
  triggers = {
    policy_test_mode = var.policy_test_mode
  }
}

output "policy_test_mode" {
  value = null_resource.policy_probe.triggers.policy_test_mode
}
