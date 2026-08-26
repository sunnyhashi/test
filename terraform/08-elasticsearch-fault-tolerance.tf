################################################################################
# TRIGGER: elasticsearch/elasticsearch-primary-node-fault-tolerance
# Policy:  Checks that Elasticsearch domains have ≥3 dedicated master nodes
#
# BUG:     The policy does:
#            cluster_config = core::try(attrs.cluster_config, [])
#            dedicated_master_enabled = core::try(local.cluster_config[0].dedicated_master_enabled, false)
#
#          core::try(attrs.cluster_config, []) returns [] when the block is absent.
#          Then local.cluster_config[0] panics on the empty list inside core::try.
#
# TRIGGER: An aws_elasticsearch_domain with NO cluster_config block.
################################################################################

provider "aws" {
  region = "us-east-1"
}

# *** TRIGGER ***
# No 'cluster_config' block is defined.
# core::try(attrs.cluster_config, []) returns [] (the fallback).
# The policy then does local.cluster_config[0] on an empty list — panic.
resource "aws_elasticsearch_domain" "no_cluster_config" {
  domain_name           = "no-cluster-config"
  elasticsearch_version = "7.10"

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  # cluster_config block intentionally omitted.
  # This produces cluster_config = [] in the plan.
  # The policy panics at:
  #   dedicated_master_enabled = core::try(local.cluster_config[0].dedicated_master_enabled, false)
}
