################################################################################
# TRIGGER: apigateway/api-gw-cache-encrypted
# Policy:  Checks that API Gateway method caching is encrypted at rest
#
# BUG:     The policy accesses attrs.settings[0] inside core::try.
#          settings is required (min 1) on aws_api_gateway_method_settings,
#          so it cannot be omitted from HCL. During a destroy plan the provider
#          represents settings = [] in plan data — [0] on [] panics inside
#          core::try.
#
# TRIGGER: Run 'terraform plan -destroy' on the resource below.
#   terraform plan -destroy -target=aws_api_gateway_method_settings.caching_enabled
#
# The destroy plan sets settings = [] in the plan attributes.
# The policy filter:
#   filter = core::try(attrs.settings[0].caching_enabled, false) == true
# panics on settings[0] because the list is empty.
################################################################################

resource "aws_api_gateway_rest_api" "example" {
  name = "example-api"
}

resource "aws_api_gateway_resource" "example" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  parent_id   = aws_api_gateway_rest_api.example.root_resource_id
  path_part   = "example"
}

resource "aws_api_gateway_method" "example" {
  rest_api_id   = aws_api_gateway_rest_api.example.id
  resource_id   = aws_api_gateway_resource.example.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_deployment" "example" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  depends_on  = [aws_api_gateway_method.example]
}

resource "aws_api_gateway_stage" "example" {
  deployment_id = aws_api_gateway_deployment.example.id
  rest_api_id   = aws_api_gateway_rest_api.example.id
  stage_name    = "prod"
}

# Valid method settings with caching enabled but NOT encrypted.
# This fails the policy enforce condition (cache_data_encrypted = false).
# Run 'terraform plan -destroy' to also trigger the settings[0] panic.
resource "aws_api_gateway_method_settings" "caching_enabled" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  stage_name  = aws_api_gateway_stage.example.stage_name
  method_path = "*/*"

  settings {
    caching_enabled      = true
    cache_data_encrypted = false  # policy enforce condition fails here
  }
}
