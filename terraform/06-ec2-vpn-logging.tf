################################################################################
# TRIGGER: ec2/ec2-vpn-connection-logging-enabled
# Policy:  Checks that both VPN tunnels have CloudWatch logging enabled
#
# BUG:     The policy accesses:
#            attrs.tunnel1_log_options[0].cloudwatch_log_options[0].log_enabled
#          inside core::try. Both 'tunnel1_log_options' and 'tunnel2_log_options'
#          are optional blocks. Without them the provider returns [].
#          Indexing [0] on [] panics inside core::try.
#
# TRIGGER: An aws_vpn_connection with NO tunnel log option blocks defined.
################################################################################
resource "aws_vpn_gateway" "example" {
  vpc_id = "vpc-00000000000000000"
}

resource "aws_customer_gateway" "example" {
  bgp_asn    = 65000
  ip_address = "172.0.0.1"
  type       = "ipsec.1"
}

# *** TRIGGER ***
# No tunnel1_log_options or tunnel2_log_options blocks.
# The provider returns tunnel1_log_options = [] and tunnel2_log_options = [].
# The policy locals:
#   tunnel1_log_enabled = core::try(attrs.tunnel1_log_options[0].cloudwatch_log_options[0].log_enabled, false)
#   tunnel2_log_enabled = core::try(attrs.tunnel2_log_options[0].cloudwatch_log_options[0].log_enabled, false)
# Both panic on [0] because the lists are empty.
resource "aws_vpn_connection" "no_logging" {
  vpn_gateway_id      = aws_vpn_gateway.example.id
  customer_gateway_id = aws_customer_gateway.example.id
  type                = "ipsec.1"
  static_routes_only  = true

  # tunnel log options intentionally omitted — triggers [0] panic
}
