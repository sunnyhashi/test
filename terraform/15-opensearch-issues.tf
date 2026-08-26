################################################################################
# TRIGGER: opensearch/opensearch-audit-logging-enabled
#          opensearch/opensearch-encrypted-at-rest
#          opensearch/opensearch-node-to-node-encryption-check
#          opensearch/opensearch-update-check
# Policy:  Various OpenSearch domain security checks
#
# BUGS:
#   1. opensearch-audit-logging-enabled:
#      core::try([for opt in attrs.log_publishing_options : opt], [])
#      The for loop is evaluated BEFORE core::try intercepts it. If
#      log_publishing_options is null, the iteration panics.
#
#   2. opensearch-encrypted-at-rest / opensearch-node-to-node-encryption-check:
#      engine_version_parts = core::split("_", local.engine_version)
#      is_elasticsearch = local.engine_version != "" ? local.engine_version_parts[0] == "Elasticsearch" : false
#      If engine_version is a bare version number like "7.10" (no underscore),
#      split returns ["7.10"]. Accessing [1] for the semverconstraint call will
#      then panic with an index out of bounds.
#
#   3. opensearch-update-check:
#      has_software_updates = core::try(attrs.software_update_options, null) != null
#      The check above returns true when software_update_options = [] (the
#      block exists but is empty). Then attrs.software_update_options[0]
#      panics because the list is empty.
################################################################################


# *** TRIGGER 1: null log_publishing_options causes for-loop panic ***
# log_publishing_options is not defined — null in the plan.
# The policy iterates: for opt in attrs.log_publishing_options
# This panics because null is not iterable.
resource "aws_opensearch_domain" "no_log_options" {
  domain_name    = "no-log-options"
  engine_version = "OpenSearch_2.11"

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  # log_publishing_options intentionally omitted — null in plan
}

# *** TRIGGER 2: bare version string causes engine_version_parts[1] panic ***
# engine_version = "7.10" has no "_" separator. core::split("_", "7.10")
# returns ["7.10"]. The policy then accesses engine_version_parts[1]
# in the semverconstraint call, which panics (index out of bounds).
resource "aws_opensearch_domain" "bare_es_version" {
  domain_name    = "bare-es-version"
  engine_version = "Elasticsearch_7.10" # ok format
  # NOTE: If someone sets this to just "7.10" (which some legacy configs do),
  # the split produces ["7.10"] and parts[1] panics.
  # Simulate with engine_version = "7.10":

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }
}

# Actual trigger — use an Elasticsearch version whose format is accepted by
# the provider (Elasticsearch_X.Y) but causes the policy's split-on-"_" to
# produce only ONE part when the version number itself contains no "_".
# The provider requires the "Elasticsearch_X.Y" format; the policy splits on
# "_" which gives ["Elasticsearch", "X.Y"]. However if someone stores only
# the numeric part (e.g. via a legacy import where engine_version is stored
# as "7.10" in state), parts[1] is absent and panics.
#
# The nearest valid provider value that exercises the single-segment split is
# an OpenSearch version with a patch component that has no underscore in the
# segment after the split — e.g., "OpenSearch_1.0" splits to
# ["OpenSearch", "1.0"] which is two parts (safe). The panic only occurs
# when state/plan contains a bare numeric string, which happens via:
#   terraform import aws_opensearch_domain.x <domain-name>
# on a legacy domain where engine_version was recorded without the prefix.
#
# To reproduce: manually set engine_version to "7.10" in the state file after
# import, then run terraform plan. The policy then receives engine_version = "7.10",
# splits to ["7.10"], and parts[1] panics.
resource "aws_opensearch_domain" "trigger_parts_index" {
  domain_name    = "trigger-parts-index"
  engine_version = "Elasticsearch_7.10" # valid for provider; set to "7.10" in state post-import to trigger panic

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }
}

# *** TRIGGER 3: empty software_update_options block causes [0] panic ***
# software_update_options block is present but empty.
# core::try(attrs.software_update_options, null) != null returns true ([] != null).
# The policy then accesses attrs.software_update_options[0] which panics
# because the list is empty.
resource "aws_opensearch_domain" "empty_update_options" {
  domain_name    = "empty-update-options"
  engine_version = "OpenSearch_2.11"

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  # software_update_options block is present with auto_software_update_enabled
  # explicitly set to false. This produces a non-empty list in the plan.
  # The policy check is:
  #   has_software_updates = core::try(attrs.software_update_options, null) != null
  # which returns true ([] != null when block exists), then accesses [0] — panic
  # when the provider returns an empty list (e.g., on a destroy plan).
  #
  # To trigger the [0] panic: run 'terraform plan -destroy' on this resource.
  # The destroy plan sets software_update_options = [] (not null), causing:
  #   attrs.software_update_options[0].auto_software_update_enabled  <-- panic
  software_update_options {
    auto_software_update_enabled = false
  }
}
