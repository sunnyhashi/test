################################################################################
# TRIGGER: ec2/ec2-client-vpn-connection-log-enabled
# Policy:  Checks Client VPN endpoints have connection logging enabled
#
# BUG:     connection_log_options is required (min 1). During a destroy plan
#          connection_log_options = [] — core::try(attrs.connection_log_options[0]...) panics.
#
# TRIGGER: terraform plan -destroy -target=aws_ec2_client_vpn_endpoint.logging_disabled
################################################################################

resource "aws_ec2_client_vpn_endpoint" "logging_disabled" {
  description            = "logging-disabled-vpn"
  server_certificate_arn = aws_acm_certificate.test_cert.arn
  client_cidr_block      = "10.0.0.0/16"

  authentication_options {
    type                       = "certificate-authentication"
    root_certificate_chain_arn = aws_acm_certificate.test_cert.arn
  }

  connection_log_options {
    enabled = false
  }
}
