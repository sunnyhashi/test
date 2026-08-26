################################################################################
# TRIGGER: ec2/ec2-client-vpn-connection-log-enabled
# Policy:  Checks that Client VPN endpoints have connection logging enabled
#
# BUG:     The policy condition directly accesses:
#            core::try(attrs.connection_log_options[0].enabled, false) == true
#          'connection_log_options' is an optional block on the resource.
#          Without it, the provider returns connection_log_options = [].
#          [0] on [] panics inside core::try.
#
# TRIGGER: An aws_ec2_client_vpn_endpoint WITHOUT a connection_log_options block.
################################################################################

provider "aws" {
  region = "us-east-1"
}

# Existing ACM certificate (referenced by ARN, not created inline, so no
# file() calls that would fail during terraform plan).
data "aws_acm_certificate" "vpn" {
  domain   = "vpn.example.com"
  statuses = ["ISSUED"]
}

# *** TRIGGER ***
# connection_log_options is a REQUIRED block on aws_ec2_client_vpn_endpoint,
# so it cannot be omitted from HCL. The trigger is a destroy plan — during
# 'terraform plan -destroy' the provider represents connection_log_options = []
# in the plan attributes, which causes the policy's condition to panic on [0].
#
# Run: terraform plan -destroy -target=aws_ec2_client_vpn_endpoint.logging_disabled
#
# The policy condition:
#   condition = core::try(attrs.connection_log_options[0].enabled, false) == true
# panics on connection_log_options[0] because the list is empty in the destroy plan.
resource "aws_ec2_client_vpn_endpoint" "logging_disabled" {
  description            = "logging-disabled-vpn"
  server_certificate_arn = data.aws_acm_certificate.vpn.arn
  client_cidr_block      = "10.0.0.0/16"

  authentication_options {
    type                       = "certificate-authentication"
    root_certificate_chain_arn = data.aws_acm_certificate.vpn.arn
  }

  # connection_log_options is required — set enabled = false so the policy
  # enforce condition fails (logging disabled), but also run -destroy to
  # trigger the [0] panic (destroy plan sets connection_log_options = []).
  connection_log_options {
    enabled = false
  }
}
