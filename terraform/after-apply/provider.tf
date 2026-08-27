terraform {
  required_providers {
    aws = {
      source  = "registry.terraform.io/hashicorp/aws"
      version = "~> 6.62"
    }
    archive = {
      source  = "registry.terraform.io/hashicorp/archive"
      version = "~> 2.8"
    }
  }
}

# Default provider — uses whatever region is configured in the environment
# (AWS_DEFAULT_REGION / AWS_REGION env var, or ~/.aws/config).
provider "aws" {}

# Route 53 query logging CloudWatch log groups MUST be created in us-east-1
# regardless of the workload region.  The alias is referenced by:
#   aws_cloudwatch_log_group.dns
#   aws_cloudwatch_log_resource_policy.route53
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}
