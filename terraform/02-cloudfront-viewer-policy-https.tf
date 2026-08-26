################################################################################
# TRIGGER: cloudfront/cloudfront-viewer-policy-https
# Policy:  Checks that all CloudFront cache behaviors use HTTPS only
#
# BUG:     The policy accesses attrs.ordered_cache_behavior[0].viewer_protocol_policy
#          inside core::try. 'ordered_cache_behavior' is fully optional. A
#          distribution without any ordered behaviors produces ordered_cache_behavior = [].
#          Indexing [0] on [] panics even inside core::try.
#
# TRIGGER: Create an aws_cloudfront_distribution with NO ordered_cache_behavior
#          blocks. The [0] index panic occurs during policy evaluation.
################################################################################



resource "aws_cloudfront_distribution" "no_ordered_behaviors" {
  enabled             = true
  default_root_object = "index.html"

  origin {
    domain_name = "example.com"
    origin_id   = "myOrigin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  # Default cache behavior — required
  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "myOrigin"
    viewer_protocol_policy = "redirect-to-https"

    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }
  }

  # *** TRIGGER ***
  # No 'ordered_cache_behavior' blocks are defined.
  # The provider returns ordered_cache_behavior = [] in the plan.
  # The policy accesses:
  #   ordered_cache_behavior = core::try(attrs.ordered_cache_behavior[0].viewer_protocol_policy, "") != "allow-all"
  # This panics because [0] is accessed on an empty list.

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
