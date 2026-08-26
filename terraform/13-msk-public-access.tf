################################################################################
# TRIGGER: msk/msk-cluster-public-access-disabled
# Policy:  Checks that MSK clusters do not have public access enabled
#
# BUG:     The policy accesses attrs.broker_node_group_info[0].connectivity_info
#          inside core::try. broker_node_group_info is required by the provider
#          schema and is modeled as a list. During a destroy plan the list
#          becomes [] in the plan data — [0] on [] panics inside core::try.
#
# TRIGGER: Run 'terraform plan -destroy' on the resource below.
#   terraform plan -destroy -target=aws_msk_cluster.no_public_access
#
# The destroy plan sets broker_node_group_info = [] which triggers:
#   connectivity_info = core::try(attrs.broker_node_group_info[0].connectivity_info, [])
################################################################################

provider "aws" {
  region = "us-east-1"
}

# Valid MSK cluster with public access disabled (no connectivity_info block).
# Run 'terraform plan -destroy' to trigger the broker_node_group_info[0] panic.
resource "aws_msk_cluster" "no_public_access" {
  cluster_name           = "no-public-access"
  kafka_version          = "3.5.1"
  number_of_broker_nodes = 3

  broker_node_group_info {
    instance_type   = "kafka.m5.large"
    client_subnets  = ["subnet-00000000000000001", "subnet-00000000000000002", "subnet-00000000000000003"]
    security_groups = ["sg-00000000000000000"]
    # connectivity_info block omitted — public access is disabled by default,
    # which also means connectivity_info[0].public_access[0].type is absent,
    # exercising the nested optional-list access in the policy.
  }
}
