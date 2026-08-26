################################################################################
# TRIGGER: cloudfront/cloudfront-origin-failover-enabled
# Policy:  Checks that CloudFront distributions have origin failover configured
#
# BUG:     The policy accesses attrs.default_cache_behavior[0].target_origin_id
#          inside core::try without a length guard. The provider schema requires
#          exactly one default_cache_behavior block, but during a destroy plan
#          the attribute is represented as [] in the plan data — and [0] on []
#          panics inside core::try.
#
# TRIGGER: Run 'terraform plan -destroy' on the resource below.
#   terraform plan -destroy -target=aws_cloudfront_distribution.no_failover
#
# The destroy plan sets default_cache_behavior = [] which triggers:
#   default_cache_target = core::try(attrs.default_cache_behavior[0].target_origin_id, "")
################################################################################


# Valid CloudFront distribution with no origin_group configured.
# Run 'terraform plan -destroy' to trigger the default_cache_behavior[0] panic.
resource "aws_cloudfront_distribution" "no_failover" {
  enabled             = true
  default_root_object = "index.html"

  origin {
    domain_name = "example.com"
    origin_id   = "primary"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "primary"
    viewer_protocol_policy = "redirect-to-https"

    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
