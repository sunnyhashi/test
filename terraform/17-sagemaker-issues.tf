################################################################################
# TRIGGER: sagemaker/sagemaker-data-quality-job-encrypt-in-transit
#          sagemaker/sagemaker-endpoint-config-prod-instance-count
# Policy:  SageMaker security and HA checks
#
# BUGS:
#   1. sagemaker-data-quality-job-encrypt-in-transit:
#      filter = core::try(attrs.network_config, null) != null
#      This check returns true when network_config = [] (not null).
#      Then: core::try(attrs.network_config[0].enable_inter_container..., false)
#      panics on [0] because the list is empty.
#
#   2. sagemaker-endpoint-config-prod-instance-count:
#      for variant in attrs.production_variants : ...
#      Despite a filter guard, locals are evaluated before filter fires.
#      Direct iteration on attrs.production_variants (not core::try) panics
#      when production_variants is null.
################################################################################

provider "aws" {
  region = "us-east-1"
}

# *** TRIGGER 1: network_config[0] panic ***
# The 'network_config' block is present but has no attribute content.
# The provider returns network_config = [] (not null) for an empty block.
# core::try(attrs.network_config, null) != null evaluates to: [] != null = true
# So has_network_config = true, and the policy evaluates:
#   core::try(attrs.network_config[0].enable_inter_container_traffic_encryption, false)
# which panics because network_config = [].
resource "aws_sagemaker_data_quality_job_definition" "empty_network_config" {
  name = "empty-network-config-trigger"

  data_quality_app_specification {
    image_uri = "123456789012.dkr.ecr.us-east-1.amazonaws.com/sagemaker-model-monitor-analyzer"
  }

  data_quality_job_input {
    endpoint_input {
      endpoint_name     = "example-endpoint"
      local_path        = "/opt/ml/processing/endpointdata"
    }
  }

  data_quality_job_output_config {
    monitoring_outputs {
      s3_output {
        local_path    = "/opt/ml/processing/output"
        s3_uri        = "s3://example-bucket/output"
        s3_upload_mode = "EndOfJob"
      }
    }
  }

  job_resources {
    cluster_config {
      instance_count    = 1
      instance_type     = "ml.m5.xlarge"
      volume_size_in_gb = 30
    }
  }

  role_arn = "arn:aws:iam::123456789012:role/sagemaker-role"

  # network_config block is required to have content — 'enable_network_isolation'
  # is optional (defaults to false) but we must set at least one attribute.
  # The bug trigger is a destroy plan: 'terraform plan -destroy' sets
  # network_config = [] in plan data, so core::try(attrs.network_config, null) != null
  # returns true ([] != null), then attrs.network_config[0] panics.
  #
  # Run: terraform plan -destroy -target=aws_sagemaker_data_quality_job_definition.empty_network_config
  network_config {
    enable_inter_container_traffic_encryption = false
    enable_network_isolation                  = false
  }
}

# *** TRIGGER 2: production_variants null iteration panic ***
# production_variants is required by the provider, but in a destroy plan
# attrs.production_variants becomes null. The locals block iterates:
#   for variant in attrs.production_variants :  <-- panics if null
# (despite the filter guard, locals are evaluated first)
#
# Run 'terraform plan -destroy -target=aws_sagemaker_endpoint_configuration.example'
resource "aws_sagemaker_endpoint_configuration" "example" {
  name = "endpoint-config-trigger"

  production_variants {
    variant_name           = "AllTraffic"
    model_name             = "example-model"
    initial_instance_count = 1  # Single instance — fails HA check too
    instance_type          = "ml.m5.xlarge"
  }
}
