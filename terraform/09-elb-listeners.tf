################################################################################
# TRIGGER: elb/elb-acm-certificate-required
#          elb/elb-predefined-security-policy-ssl-check
#          elb/elb-tls-https-listeners-only
# Policy:  Various checks on Classic Load Balancer listeners
#
# BUG:     All three policies iterate over 'attrs.listener' directly inside
#          their locals blocks:
#            for listener in attrs.listener : ...
#          The provider requires at least one listener block, but during a
#          destroy plan attrs.listener becomes null in the plan data.
#          Sentinel evaluates locals before applying the filter, so the direct
#          iteration panics before the null guard fires.
#
# TRIGGER: Run 'terraform plan -destroy' on the resource below.
#   terraform plan -destroy -target=aws_elb.http_only
#
# The destroy plan sets attrs.listener = null which triggers:
#   non_compliant_listeners = [for listener in attrs.listener : ...]  <-- panic
################################################################################



# Valid Classic ELB with an HTTP-only listener (also fails the policy enforce
# condition for elb-tls-https-listeners-only). Run 'terraform plan -destroy'
# to trigger the null-iteration panic in all three elb policies.
resource "aws_elb" "http_only" {
  name            = "http-only-elb"
  internal        = false
  security_groups = ["sg-00000000000000000"]
  subnets         = ["subnet-00000000000000000"]

  listener {
    instance_port     = 80
    instance_protocol = "HTTP"
    lb_port           = 80
    lb_protocol       = "HTTP"
  }
}
