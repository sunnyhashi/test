# =============================================================================
# test.tf — Post-apply policy regression fixture
#
# Covers all 66 policies whose Sentinel evaluation was "unknown" at plan time.
# Each resource group has a pass resource (compliant) and a fail resource
# (intentional_violation) so both branches of every policy are exercised after
# terraform apply resolves all computed attributes.
#
# This file lives in the existing repo and uses shared infrastructure from:
#   networking.tf  — aws_vpc.main, aws_subnet.private[*], aws_subnet.public[*]
#   provider.tf    — provider "aws" and provider "aws" alias "us_east_1"
#   versions.tf    — terraform required_providers
# =============================================================================

# =============================================================================
# Data sources
# =============================================================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# =============================================================================
# Shared KMS key (used across multiple resource groups)
# =============================================================================

resource "aws_kms_key" "pat_main" {
  description             = "post-apply-policy-test shared key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_kms_alias" "pat_main" {
  name          = "alias/post-apply-policy-test"
  target_key_id = aws_kms_key.pat_main.key_id
}

# =============================================================================
# 1. aws_acm_certificate.certificate_renewal_check
#    Policy: acm-certificate-expiration-check-policy.policy.hcl
#    Unknown because: renewal_eligibility / not_after are compute-only attributes
# =============================================================================

resource "aws_acm_certificate" "pass" {
  domain_name       = "pass.post-apply-test.internal"
  validation_method = "DNS"

  lifecycle { create_before_destroy = true }
}

resource "aws_acm_certificate" "weak_key_fail" {
  domain_name       = "weak.post-apply-test.internal"
  validation_method = "DNS"
  key_algorithm     = "RSA_1024" # intentional_violation: weak key

  lifecycle { create_before_destroy = true }

  tags = {
    compliance_test = "intentional_violation"
    controls        = "ACM.2"
  }
}

# =============================================================================
# 2. aws_msk_cluster.encryption_in_transit
#    Policy: msk-in-cluster-node-require-tls-policy.policy.hcl
# 3. aws_msk_cluster.public_access_disabled
#    Policy: msk-cluster-public-access-disabled-policy.policy.hcl
#    Unknown because: broker_node_group_info.connectivity_info is computed post-apply
# =============================================================================

resource "aws_security_group" "msk" {
  name        = "post-apply-msk"
  description = "MSK post-apply policy test"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_msk_configuration" "test" {
  name           = "post-apply-policy-test"
  kafka_versions = ["3.6.0"]

  server_properties = <<-PROPS
    auto.create.topics.enable=false
    delete.topic.enable=true
  PROPS
}

resource "aws_cloudwatch_log_group" "msk" {
  name              = "/aws/msk/post-apply-policy-test"
  retention_in_days = 7
}

# pass: TLS only in-transit, no public access
resource "aws_msk_cluster" "pass" {
  cluster_name           = "post-apply-test-msk-pass"
  kafka_version          = "3.6.0"
  number_of_broker_nodes = 3

  broker_node_group_info {
    instance_type   = "kafka.t3.small"
    client_subnets  = aws_subnet.private[*].id
    security_groups = [aws_security_group.msk.id]

    storage_info {
      ebs_storage_info { volume_size = 20 }
    }

    connectivity_info {
      public_access { type = "DISABLED" } # satisfies msk-cluster-public-access-disabled
    }
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"        # satisfies msk-in-cluster-node-require-tls
      in_cluster    = true
    }
  }

  configuration_info {
    arn      = aws_msk_configuration.test.arn
    revision = aws_msk_configuration.test.latest_revision
  }

  logging_info {
    broker_logs {
      cloudwatch_logs {
        enabled   = true
        log_group = aws_cloudwatch_log_group.msk.name
      }
    }
  }
}

# fail: PLAINTEXT transit + public access enabled
# intentional_violation: client_broker = PLAINTEXT, public_access = SERVICE_PROVIDED_EIPS
resource "aws_msk_cluster" "transit_fail" {
  cluster_name           = "post-apply-test-msk-transit-fail"
  kafka_version          = "3.6.0"
  number_of_broker_nodes = 3

  broker_node_group_info {
    instance_type   = "kafka.t3.small"
    client_subnets  = aws_subnet.private[*].id
    security_groups = [aws_security_group.msk.id]

    storage_info {
      ebs_storage_info { volume_size = 20 }
    }

    connectivity_info {
      public_access { type = "SERVICE_PROVIDED_EIPS" } # intentional_violation: MSK.3
    }
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "PLAINTEXT" # intentional_violation: MSK.1
      in_cluster    = true
    }
  }

  configuration_info {
    arn      = aws_msk_configuration.test.arn
    revision = aws_msk_configuration.test.latest_revision
  }

  logging_info {
    broker_logs {
      cloudwatch_logs {
        enabled   = true
        log_group = aws_cloudwatch_log_group.msk.name
      }
    }
  }

  tags = {
    compliance_test = "intentional_violation"
    controls        = "MSK.1,MSK.3"
  }
}

# =============================================================================
# 4. aws_rds_cluster.no_default_port_cluster
# 5. aws_rds_cluster.multi_az_enabled
#    Policy: rds-no-default-ports-policy / rds-cluster-multi-az-enabled-policy
#    Unknown because: availability_zones is computed post-apply
# =============================================================================

resource "aws_db_subnet_group" "test" {
  name       = "post-apply-policy-test"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_security_group" "rds" {
  name        = "post-apply-rds"
  description = "RDS post-apply policy test"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# pass: non-default port (3307), multi-AZ via 3 availability_zones
resource "aws_rds_cluster" "pass" {
  cluster_identifier  = "post-apply-aurora-pass"
  engine              = "aurora-mysql"
  engine_version      = "8.0.mysql_aurora.3.05.2"
  master_username     = "clusteradmin"
  master_password     = var.db_password
  port                = 3307 # non-default — satisfies rds-no-default-ports
  availability_zones  = var.availability_zones # 3 AZs — satisfies multi-az

  storage_encrypted      = true
  kms_key_id             = aws_kms_key.pat_main.arn
  db_subnet_group_name   = aws_db_subnet_group.test.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  backup_retention_period              = 7
  deletion_protection                  = true
  iam_database_authentication_enabled  = true
  copy_tags_to_snapshot                = true
  skip_final_snapshot                  = true
  apply_immediately                    = true
}

# fail: default port (3306), single AZ
# intentional_violation: port = 3306, availability_zones = single zone
resource "aws_rds_cluster" "default_port_fail" {
  cluster_identifier  = "post-apply-aurora-port-fail"
  engine              = "aurora-mysql"
  engine_version      = "8.0.mysql_aurora.3.05.2"
  master_username     = "clusteradmin"
  master_password     = var.db_password
  port                = 3306 # intentional_violation: default MySQL port
  availability_zones  = [var.availability_zones[0]] # intentional_violation: single AZ

  storage_encrypted      = false
  db_subnet_group_name   = aws_db_subnet_group.test.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  backup_retention_period = 7
  deletion_protection     = true
  skip_final_snapshot     = true
  apply_immediately       = true

  tags = {
    compliance_test = "intentional_violation"
    controls        = "RDS.No_Default_Port,RDS.MultiAZ"
  }
}

# =============================================================================
# 6.  aws_instance.ssm_managed_prerequisite
# 7.  aws_instance.root_encryption_required
# 8.  aws_instance.ebs_encryption_required
# 9.  aws_instance.no_multiple_enis
# 10. aws_instance.no_public_ipv4
# 11. aws_instance.stopped_instances_check
#     Policies: ec2-managedinstance / encrypted-volumes / ec2-instance-multiple-eni-check /
#               ec2-instance-no-public-ip / ec2-stopped-instance-days-check
#     Unknown because: root_block_device, ebs_block_device, network_interfaces,
#                      associate_public_ip_address are computed post-apply
# =============================================================================

resource "aws_iam_role" "ec2_instance" {
  name = "post-apply-ec2-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ec2_instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2" {
  name = "post-apply-ec2-instance-profile"
  role = aws_iam_role.ec2_instance.name
}

resource "aws_security_group" "ec2" {
  name        = "post-apply-ec2"
  description = "EC2 post-apply policy test"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# pass: private subnet, encrypted root + EBS, single ENI, SSM user-data, IMDSv2
resource "aws_instance" "pass" {
  ami                         = data.aws_ami.amazon_linux_2023.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.private[0].id
  iam_instance_profile        = aws_iam_instance_profile.ec2.name
  associate_public_ip_address = false

  user_data = base64encode(<<-EOF
    #!/bin/bash
    yum install -y amazon-ssm-agent
    systemctl enable amazon-ssm-agent
    systemctl start amazon-ssm-agent
  EOF
  )

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    encrypted             = true
    kms_key_id            = aws_kms_key.pat_main.arn
    delete_on_termination = true
  }

  ebs_block_device {
    device_name           = "/dev/sdf"
    volume_type           = "gp3"
    volume_size           = 10
    encrypted             = true
    kms_key_id            = aws_kms_key.pat_main.arn
    delete_on_termination = true
  }

  vpc_security_group_ids = [aws_security_group.ec2.id]

  tags = { Name = "post-apply-ec2-pass" }
}

# fail: public IP, unencrypted root+EBS, no SSM user-data
# intentional_violation: associate_public_ip_address=true, encrypted=false
resource "aws_instance" "app_fail" {
  ami                         = data.aws_ami.amazon_linux_2023.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public[0].id
  iam_instance_profile        = aws_iam_instance_profile.ec2.name
  associate_public_ip_address = true # intentional_violation: EC2.9

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    encrypted             = false # intentional_violation: EC2.3/EC2.7
    delete_on_termination = true
  }

  ebs_block_device {
    device_name           = "/dev/sdf"
    volume_type           = "gp3"
    volume_size           = 10
    encrypted             = false # intentional_violation: EC2.3
    delete_on_termination = true
  }

  vpc_security_group_ids = [aws_security_group.ec2.id]

  tags = {
    Name            = "post-apply-ec2-fail"
    compliance_test = "intentional_violation"
    controls        = "EC2.3,EC2.9,EC2.10"
  }
}

# =============================================================================
# 12. aws_db_instance.no_public_subnet_igw
#     Policy: rds-instance-subnet-igw-check-policy.policy.hcl
#     Unknown because: subnet → route_table association is computed post-apply
# =============================================================================

# pass: private subnet (route table has NAT, no IGW)
resource "aws_db_instance" "pass" {
  identifier             = "post-apply-rds-pass"
  engine                 = "mysql"
  engine_version         = "8.0.35"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  storage_type           = "gp3"
  storage_encrypted      = true
  kms_key_id             = aws_kms_key.pat_main.arn
  db_subnet_group_name   = aws_db_subnet_group.test.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  username               = "dbadmin"
  password               = var.db_password
  port                   = 3307
  publicly_accessible    = false
  multi_az               = true
  deletion_protection    = true
  skip_final_snapshot    = true
  apply_immediately      = true

  backup_retention_period    = 7
  auto_minor_version_upgrade = true
  iam_database_authentication_enabled = true
  copy_tags_to_snapshot      = true

  enabled_cloudwatch_logs_exports = ["audit", "error", "general", "slowquery"]

  tags = { Name = "post-apply-rds-pass" }
}

# fail: placed in a public subnet whose route table has an IGW route
# intentional_violation: db_subnet_group pointing to public subnets
resource "aws_db_subnet_group" "public" {
  name       = "post-apply-rds-public-subnet-group"
  subnet_ids = aws_subnet.public[*].id
}

resource "aws_db_instance" "public_subnet_fail" {
  identifier             = "post-apply-rds-igw-fail"
  engine                 = "mysql"
  engine_version         = "8.0.35"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  storage_type           = "gp3"
  storage_encrypted      = true
  kms_key_id             = aws_kms_key.pat_main.arn
  db_subnet_group_name   = aws_db_subnet_group.public.name # intentional_violation
  vpc_security_group_ids = [aws_security_group.rds.id]
  username               = "dbadmin"
  password               = var.db_password
  publicly_accessible    = false
  deletion_protection    = false
  skip_final_snapshot    = true
  apply_immediately      = true

  tags = {
    Name            = "post-apply-rds-igw-fail"
    compliance_test = "intentional_violation"
    controls        = "RDS.NoPublicSubnet"
  }
}

# =============================================================================
# 13. aws_launch_template.no_public_ip
# 14. aws_launch_template.ebs_encryption_enabled
#     Policies: ec2-launch-template-public-ip-disabled / ec2-launch-templates-ebs-volume-encrypted
#     Unknown because: network_interfaces and block_device_mappings are computed post-apply
# =============================================================================

# pass: no public IP, encrypted EBS, IMDSv2
resource "aws_launch_template" "pass" {
  name          = "post-apply-lt-pass"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.ec2.id]
    delete_on_termination       = true
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_type           = "gp3"
      volume_size           = 20
      encrypted             = true
      kms_key_id            = aws_kms_key.pat_main.arn
      delete_on_termination = true
    }
  }
}

# fail: public IP, unencrypted EBS, IMDSv1
# intentional_violation: associate_public_ip_address=true, encrypted=false, http_tokens=optional
resource "aws_launch_template" "fail" {
  name          = "post-apply-lt-fail"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional" # intentional_violation: EC2.170
    http_put_response_hop_limit = 1
  }

  network_interfaces {
    associate_public_ip_address = true # intentional_violation: EC2.25
    security_groups             = [aws_security_group.ec2.id]
    delete_on_termination       = true
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_type           = "gp3"
      volume_size           = 20
      encrypted             = false # intentional_violation: EC2.LT.EBS
      delete_on_termination = true
    }
  }

  tags = {
    compliance_test = "intentional_violation"
    controls        = "EC2.25,EC2.170"
  }
}

# =============================================================================
# 15. aws_cloudtrail.multi_region_trail_required
#     Policy: multi-region-cloudtrail-enabled-policy.policy.hcl
#     Unknown because: cloud_watch_logs_group_arn contains a computed token at plan time
# =============================================================================

resource "aws_s3_bucket" "cloudtrail" {
  bucket        = "post-apply-ct-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/post-apply-test"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.pat_main.arn
}

resource "aws_iam_role" "cloudtrail_cw" {
  name = "post-apply-cloudtrail-cw-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "cloudtrail_cw" {
  role = aws_iam_role.cloudtrail_cw.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

# pass: multi-region + CloudWatch logging (arn with :* suffix is the computed token)
resource "aws_cloudtrail" "pass" {
  name                          = "post-apply-ct-pass"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  kms_key_id                    = aws_kms_key.pat_main.arn
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cw.arn

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}

# fail: single-region, no CloudWatch
# intentional_violation: is_multi_region_trail=false, cloud_watch_logs_group_arn omitted
resource "aws_cloudtrail" "cw_fail" {
  name                          = "post-apply-ct-cw-fail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  s3_key_prefix                 = "cw-fail"
  is_multi_region_trail         = false # intentional_violation
  enable_log_file_validation    = true
  include_global_service_events = true
  # cloud_watch_logs_group_arn omitted — intentional_violation

  depends_on = [aws_s3_bucket_policy.cloudtrail]

  tags = {
    compliance_test = "intentional_violation"
    controls        = "CloudTrail.5,CIS-3.1"
  }
}

# =============================================================================
# 16. aws_cloudfront_distribution.no_deprecated_ssl_protocols_all
# 17. aws_cloudfront_distribution.no_deprecated_ssl_protocols
# 18. aws_cloudfront_distribution.default-root-object-configured
# 19. aws_cloudfront_distribution.oac_required
# 20. aws_cloudfront_distribution.trusted_key_groups_required
# 21. aws_cloudfront_distribution.lambda_url_oac_required
#     Unknown because: viewer_certificate, origin OAC IDs, and trusted_key_groups
#                      are computed from other resources at plan time
# =============================================================================

resource "aws_s3_bucket" "cf_origin" {
  bucket        = "post-apply-cf-origin-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "cf_origin" {
  bucket                  = aws_s3_bucket.cf_origin.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudfront_origin_access_control" "main" {
  name                              = "post-apply-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_s3_bucket" "cf_logs" {
  bucket        = "post-apply-cf-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "cf_logs" {
  bucket = aws_s3_bucket.cf_logs.id
  rule { object_ownership = "BucketOwnerPreferred" }
}

# pass: default_root_object set, OAC configured, https redirect, modern TLS
resource "aws_cloudfront_distribution" "pass" {
  enabled             = true
  default_root_object = "index.html"
  price_class         = "PriceClass_100"

  origin {
    domain_name              = aws_s3_bucket.cf_origin.bucket_regional_domain_name
    origin_id                = "s3-origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.main.id
  }

  default_cache_behavior {
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "s3-origin"

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
    minimum_protocol_version       = "TLSv1.2_2021"
    ssl_support_method             = "sni-only"
  }

  logging_config {
    bucket = "${aws_s3_bucket.cf_logs.id}.s3.amazonaws.com"
    prefix = "cf-pass/"
  }
}

# fail: no default_root_object, no OAC
# intentional_violation: default_root_object="" (CloudFront.1)
resource "aws_cloudfront_distribution" "root_object_fail" {
  enabled             = true
  default_root_object = "" # intentional_violation: CloudFront.1
  price_class         = "PriceClass_100"

  origin {
    domain_name = aws_s3_bucket.cf_origin.bucket_regional_domain_name
    origin_id   = "s3-origin"
    # origin_access_control_id omitted — intentional_violation: CloudFront.13
  }

  default_cache_behavior {
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "s3-origin"

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
    minimum_protocol_version       = "TLSv1.2_2021"
    ssl_support_method             = "sni-only"
  }

  logging_config {
    bucket = "${aws_s3_bucket.cf_logs.id}.s3.amazonaws.com"
    prefix = "cf-root-fail/"
  }

  tags = {
    compliance_test = "intentional_violation"
    controls        = "CloudFront.1,CloudFront.13"
  }
}

# =============================================================================
# 22. aws_eks_cluster.endpoint_no_public_access
#     Policy: eks-endpoint-no-public-access-policy.policy.hcl
#     Unknown because: vpc_config.endpoint_public_access is computed post-apply
# =============================================================================

resource "aws_iam_role" "eks_cluster" {
  name = "post-apply-eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

# pass: endpoint_public_access = false
resource "aws_eks_cluster" "pass" {
  name     = "post-apply-eks-pass"
  role_arn = aws_iam_role.eks_cluster.arn
  version  = "1.33"

  vpc_config {
    subnet_ids              = aws_subnet.private[*].id
    endpoint_public_access  = false # satisfies eks-endpoint-no-public-access
    endpoint_private_access = true
  }

  depends_on = [aws_iam_role_policy_attachment.eks_cluster_policy]
}

# fail: endpoint_public_access = true
# intentional_violation: endpoint_public_access = true
resource "aws_eks_cluster" "public_fail" {
  name     = "post-apply-eks-public-fail"
  role_arn = aws_iam_role.eks_cluster.arn
  version  = "1.33"

  vpc_config {
    subnet_ids             = aws_subnet.private[*].id
    endpoint_public_access = true # intentional_violation: EKS.1
  }

  depends_on = [aws_iam_role_policy_attachment.eks_cluster_policy]

  tags = {
    compliance_test = "intentional_violation"
    controls        = "EKS.1"
  }
}

# =============================================================================
# 23. aws_opensearch_domain.fine_grained_access_control
# 24. aws_opensearch_domain.latest_software_update_installed
# 25. aws_opensearch_domain.data_node_fault_tolerance
#     Policies: opensearch-access-control-enabled / opensearch-update-check /
#               opensearch-data-node-fault-tolerance
#     Unknown because: advanced_security_options and software_update_options are computed
# =============================================================================

resource "aws_security_group" "opensearch" {
  name        = "post-apply-opensearch"
  description = "OpenSearch post-apply policy test"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_cloudwatch_log_group" "opensearch" {
  name              = "/aws/opensearch/post-apply-test"
  retention_in_days = 7
}

# pass: FGAC enabled, auto software updates, 3 data nodes (zone awareness)
resource "aws_opensearch_domain" "pass" {
  domain_name    = "post-apply-os-pass"
  engine_version = "OpenSearch_2.13"

  cluster_config {
    instance_type          = "t3.small.search"
    instance_count         = 3 # satisfies data-node-fault-tolerance
    zone_awareness_enabled = true
    zone_awareness_config  { availability_zone_count = 3 }
  }

  vpc_options {
    subnet_ids         = slice(aws_subnet.private[*].id, 0, 3)
    security_group_ids = [aws_security_group.opensearch.id]
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 20
    volume_type = "gp3"
  }

  encrypt_at_rest {
    enabled    = true
    kms_key_id = aws_kms_key.pat_main.arn
  }
  node_to_node_encryption { enabled = true }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-PFS-2023-10"
  }

  advanced_security_options {
    enabled                        = true # satisfies opensearch-access-control-enabled
    internal_user_database_enabled = true
    master_user_options {
      master_user_name     = "admin"
      master_user_password = "Ch@ngeMe2024!"
    }
  }

  software_update_options {
    auto_software_update_enabled = true # satisfies opensearch-update-check
  }

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch.arn
    log_type                 = "ES_APPLICATION_LOGS"
  }
  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch.arn
    log_type                 = "AUDIT_LOGS"
  }
}

# fail: FGAC disabled, no auto update, single node
# intentional_violation: advanced_security_options.enabled=false, instance_count=1
resource "aws_opensearch_domain" "access_control_fail" {
  domain_name    = "post-apply-os-fgac-fail"
  engine_version = "OpenSearch_2.13"

  cluster_config {
    instance_type          = "t3.small.search"
    instance_count         = 1 # intentional_violation: data-node-fault-tolerance
    zone_awareness_enabled = false
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 20
    volume_type = "gp3"
  }

  encrypt_at_rest         { enabled = true }
  node_to_node_encryption { enabled = true }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  advanced_security_options {
    enabled                        = false # intentional_violation: OpenSearch.7
    internal_user_database_enabled = false
  }

  software_update_options {
    auto_software_update_enabled = false # intentional_violation: OpenSearch.update-check
  }

  tags = {
    compliance_test = "intentional_violation"
    controls        = "OpenSearch.7,OpenSearch.UpdateCheck"
  }
}

# =============================================================================
# 26. aws_sqs_queue.encryption_required
# 27. aws_sqs_queue.no_public_access_inline
#     Policies: sqs-queue-encrypted / sqs-queue-no-public-access
#     Unknown because: policy attribute and kms_master_key_id are computed post-apply
# =============================================================================

# pass: KMS encrypted, restricted policy
resource "aws_sqs_queue" "pass" {
  name              = "post-apply-sqs-pass"
  kms_master_key_id = aws_kms_key.pat_main.arn
}

data "aws_iam_policy_document" "sqs_pass" {
  statement {
    effect    = "Allow"
    actions   = ["sqs:SendMessage", "sqs:ReceiveMessage"]
    resources = [aws_sqs_queue.pass.arn]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_sqs_queue_policy" "pass" {
  queue_url = aws_sqs_queue.pass.id
  policy    = data.aws_iam_policy_document.sqs_pass.json
}

# fail: unencrypted, public principal
# intentional_violation: no kms key, wildcard principal
resource "aws_sqs_queue" "encrypted_fail" {
  name = "post-apply-sqs-encrypted-fail"
  # kms_master_key_id omitted — intentional_violation: SQS.1
}

resource "aws_sqs_queue" "public_fail" {
  name              = "post-apply-sqs-public-fail"
  kms_master_key_id = aws_kms_key.pat_main.arn
}

data "aws_iam_policy_document" "sqs_public_fail" {
  statement {
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = ["*"]
    principals {
      type        = "*" # intentional_violation: SQS.3
      identifiers = ["*"]
    }
  }
}

resource "aws_sqs_queue_policy" "public_fail" {
  queue_url = aws_sqs_queue.public_fail.id
  policy    = data.aws_iam_policy_document.sqs_public_fail.json
}

# =============================================================================
# 28. aws_efs_mount_target.no_public_subnet
#     Policy: efs-mount-target-public-accessible-policy.policy.hcl
#     Unknown because: subnet map_public_ip_on_launch is resolved post-apply
# =============================================================================

resource "aws_security_group" "efs" {
  name        = "post-apply-efs"
  description = "EFS post-apply policy test"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_efs_file_system" "pass" {
  encrypted  = true
  kms_key_id = aws_kms_key.pat_main.arn
}

# pass: mount target in private subnet (map_public_ip_on_launch = false)
resource "aws_efs_mount_target" "pass" {
  count           = 3
  file_system_id  = aws_efs_file_system.pass.id
  subnet_id       = aws_subnet.private[count.index].id
  security_groups = [aws_security_group.efs.id]
}

# fail: mount target in public subnet
# intentional_violation: public subnet has map_public_ip_on_launch = true
resource "aws_subnet" "public_efs_fail" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.10.200.0/24"
  availability_zone       = var.availability_zones[0]
  map_public_ip_on_launch = true # intentional_violation: EFS.MountTarget

  tags = {
    Name            = "post-apply-efs-public-subnet-fail"
    compliance_test = "intentional_violation"
  }
}

resource "aws_efs_mount_target" "public_fail" {
  file_system_id  = aws_efs_file_system.pass.id
  subnet_id       = aws_subnet.public_efs_fail.id
  security_groups = [aws_security_group.efs.id]
}

# =============================================================================
# 29. aws_redshift_cluster.unrestricted-port-access
#     Policy: redshift-unrestricted-port-access-policy.policy.hcl
#     Unknown because: vpc_security_group_ids sg rules are computed post-apply
# =============================================================================

resource "aws_security_group" "redshift" {
  name        = "post-apply-redshift"
  description = "Redshift post-apply policy test"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Redshift from VPC only"
    from_port   = 5439
    to_port     = 5439
    protocol    = "tcp"
    cidr_blocks = ["10.10.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "redshift_open" {
  name        = "post-apply-redshift-open"
  description = "Redshift open access - intentional violation"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Redshift from anywhere - intentional violation"
    from_port   = 5439
    to_port     = 5439
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # intentional_violation: Redshift.9
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_redshift_subnet_group" "test" {
  name       = "post-apply-redshift"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_redshift_cluster" "pass" {
  cluster_identifier        = "post-apply-redshift-pass"
  database_name             = "appdb"
  master_username           = "clusteradmin"
  master_password           = var.db_password
  node_type                 = "dc2.large"
  cluster_type              = "single-node"
  cluster_subnet_group_name = aws_redshift_subnet_group.test.name
  vpc_security_group_ids    = [aws_security_group.redshift.id] # restricted
  encrypted                 = true
  kms_key_id                = aws_kms_key.pat_main.arn
  publicly_accessible       = false
  skip_final_snapshot       = true
  automated_snapshot_retention_period = 7
}

resource "aws_redshift_cluster" "unrestricted_fail" {
  cluster_identifier        = "post-apply-redshift-open-fail"
  database_name             = "appdb"
  master_username           = "clusteradmin"
  master_password           = var.db_password
  node_type                 = "dc2.large"
  cluster_type              = "single-node"
  cluster_subnet_group_name = aws_redshift_subnet_group.test.name
  vpc_security_group_ids    = [aws_security_group.redshift_open.id] # intentional_violation
  encrypted                 = true
  kms_key_id                = aws_kms_key.pat_main.arn
  publicly_accessible       = false
  skip_final_snapshot       = true

  tags = {
    compliance_test = "intentional_violation"
    controls        = "Redshift.9"
  }
}

# =============================================================================
# 30. aws_sns_topic.no_public_access_inline
#     Policy: sns-topic-no-public-access-policy.policy.hcl
#     Unknown because: policy attribute is a computed JSON string post-apply
# =============================================================================

resource "aws_sns_topic" "pass" {
  name              = "post-apply-sns-pass"
  kms_master_key_id = aws_kms_key.pat_main.arn
}

data "aws_iam_policy_document" "sns_pass" {
  statement {
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.pass.arn]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_sns_topic_policy" "pass" {
  arn    = aws_sns_topic.pass.arn
  policy = data.aws_iam_policy_document.sns_pass.json
}

resource "aws_sns_topic" "public_fail" {
  name              = "post-apply-sns-public-fail"
  kms_master_key_id = aws_kms_key.pat_main.arn
}

data "aws_iam_policy_document" "sns_public_fail" {
  statement {
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.public_fail.arn]
    principals {
      type        = "*" # intentional_violation: SNS.2
      identifiers = ["*"]
    }
  }
}

resource "aws_sns_topic_policy" "public_fail" {
  arn    = aws_sns_topic.public_fail.arn
  policy = data.aws_iam_policy_document.sns_public_fail.json
}

# =============================================================================
# 31. aws_lb.http_to_https_redirect
# 32. aws_lb.multiple_az_required
# 33. aws_lb_listener.secure_protocol_check
# 34. aws_lb_target_group.encrypted_health_check
#     Policies: alb-http-to-https-redirection-check / elbv2-multiple-az /
#               elbv2-listener-encryption-in-transit / elbv2-targetgroup-healthcheck-protocol-encrypted
#     Unknown because: listeners, subnet AZ mapping, and target group protocol are post-apply
# =============================================================================

resource "aws_security_group" "alb" {
  name        = "post-apply-alb"
  description = "ALB post-apply policy test"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# pass target group: HTTPS protocol (satisfies elbv2-targetgroup-healthcheck-protocol-encrypted)
resource "aws_lb_target_group" "https_pass" {
  name        = "post-apply-tg-https-pass"
  port        = 443
  protocol    = "HTTPS"
  vpc_id      = aws_vpc.main.id
  target_type = "instance"

  health_check {
    path     = "/health"
    protocol = "HTTPS" # satisfies elbv2-targetgroup-healthcheck-protocol-encrypted
    matcher  = "200"
  }
}

# fail target group: HTTP protocol
# intentional_violation: protocol = HTTP
resource "aws_lb_target_group" "http_fail" {
  name        = "post-apply-tg-http-fail"
  port        = 8080
  protocol    = "HTTP" # intentional_violation
  vpc_id      = aws_vpc.main.id
  target_type = "instance"

  health_check {
    path     = "/health"
    protocol = "HTTP" # intentional_violation: elbv2-targetgroup-healthcheck-protocol-encrypted
    matcher  = "200"
  }

  tags = {
    compliance_test = "intentional_violation"
    controls        = "ELB.TargetGroupProtocol"
  }
}

resource "aws_acm_certificate" "alb" {
  domain_name       = "post-apply-alb.internal"
  validation_method = "DNS"
  lifecycle { create_before_destroy = true }
}

# pass ALB: multi-AZ (3 subnets), HTTP→HTTPS redirect, deletion protection
resource "aws_lb" "pass" {
  name                       = "post-apply-alb-pass"
  load_balancer_type         = "application"
  internal                   = false
  subnets                    = aws_subnet.public[*].id # 3 AZs satisfies elbv2-multiple-az
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
  enable_deletion_protection = true

  access_logs {
    bucket  = aws_s3_bucket.cloudtrail.id
    prefix  = "alb-pass"
    enabled = true
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.pass.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.pass.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.alb.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.https_pass.arn
  }
}

# fail ALB: single AZ, no redirect
# intentional_violation: single subnet (1 AZ), plain HTTP listener
resource "aws_lb" "multiaz_fail" {
  name               = "post-apply-alb-singleaz-fail"
  load_balancer_type = "application"
  internal           = true
  subnets            = [aws_subnet.public[0].id] # intentional_violation: single AZ
  security_groups    = [aws_security_group.alb.id]

  tags = {
    compliance_test = "intentional_violation"
    controls        = "ELB.MultiAZ"
  }
}

resource "aws_lb_listener" "http_forward_fail" {
  load_balancer_arn = aws_lb.multiaz_fail.arn
  port              = 80
  protocol          = "HTTP" # intentional_violation: no redirect

  default_action {
    type             = "forward" # intentional_violation: should redirect to HTTPS
    target_group_arn = aws_lb_target_group.http_fail.arn
  }
}

# =============================================================================
# 35. aws_api_gateway_stage.waf_association_required
# 36. aws_api_gateway_method_settings.execution_logging_level
#     Policies: api-gw-associated-with-waf / api-gw-execution-logging-enabled
#     Unknown because: waf association ARN and method settings are computed post-apply
# =============================================================================

resource "aws_api_gateway_rest_api" "test" {
  name = "post-apply-api-test"
  endpoint_configuration { types = ["REGIONAL"] }
}

resource "aws_api_gateway_resource" "root" {
  rest_api_id = aws_api_gateway_rest_api.test.id
  parent_id   = aws_api_gateway_rest_api.test.root_resource_id
  path_part   = "{proxy+}"
}

resource "aws_api_gateway_method" "get" {
  rest_api_id   = aws_api_gateway_rest_api.test.id
  resource_id   = aws_api_gateway_resource.root.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "mock" {
  rest_api_id = aws_api_gateway_rest_api.test.id
  resource_id = aws_api_gateway_resource.root.id
  http_method = aws_api_gateway_method.get.http_method
  type        = "MOCK"
  request_templates = { "application/json" = jsonencode({ statusCode = 200 }) }
}

resource "aws_api_gateway_deployment" "test" {
  rest_api_id = aws_api_gateway_rest_api.test.id
  depends_on  = [aws_api_gateway_method.get, aws_api_gateway_integration.mock]
  lifecycle   { create_before_destroy = true }
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/apigateway/post-apply-test"
  retention_in_days = 7
}

resource "aws_wafv2_web_acl" "test" {
  name  = "post-apply-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "post-apply-waf"
    sampled_requests_enabled   = true
  }
}

# pass stage: WAF associated, logging enabled
resource "aws_api_gateway_stage" "pass" {
  rest_api_id           = aws_api_gateway_rest_api.test.id
  deployment_id         = aws_api_gateway_deployment.test.id
  stage_name            = "prod"
  xray_tracing_enabled  = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api.arn
    format          = "$context.requestId $context.status"
  }
}

resource "aws_wafv2_web_acl_association" "pass" {
  resource_arn = aws_api_gateway_stage.pass.arn
  web_acl_arn  = aws_wafv2_web_acl.test.arn
}

resource "aws_api_gateway_method_settings" "pass" {
  rest_api_id = aws_api_gateway_rest_api.test.id
  stage_name  = aws_api_gateway_stage.pass.stage_name
  method_path = "*/*"

  settings {
    logging_level      = "INFO" # satisfies execution_logging_level
    metrics_enabled    = true
    caching_enabled    = false
  }
}

# fail stage: no WAF, no logging
# intentional_violation: no waf association, logging_level = OFF
resource "aws_api_gateway_stage" "waf_fail" {
  rest_api_id  = aws_api_gateway_rest_api.test.id
  deployment_id = aws_api_gateway_deployment.test.id
  stage_name   = "waf-fail"
  # no waf association — intentional_violation: APIGateway.4

  tags = {
    compliance_test = "intentional_violation"
    controls        = "APIGateway.4"
  }
}

resource "aws_api_gateway_method_settings" "logging_fail" {
  rest_api_id = aws_api_gateway_rest_api.test.id
  stage_name  = aws_api_gateway_stage.waf_fail.stage_name
  method_path = "*/*"

  settings {
    logging_level   = "OFF" # intentional_violation: APIGateway.1
    metrics_enabled = false
    caching_enabled = false
  }
}

# =============================================================================
# 37. aws_dynamodb_table.pitr_enabled
#     Policy: dynamodb-pitr-enabled-policy.policy.hcl
#     Unknown because: point_in_time_recovery.enabled is post-apply computed attribute
# =============================================================================

# pass: PITR enabled
resource "aws_dynamodb_table" "pass" {
  name         = "post-apply-dynamo-pass"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true # satisfies dynamodb-pitr-enabled
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.pat_main.arn
  }

  deletion_protection_enabled = true
}

# fail: PITR disabled
# intentional_violation: point_in_time_recovery.enabled = false
resource "aws_dynamodb_table" "pitr_fail" {
  name         = "post-apply-dynamo-pitr-fail"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = false # intentional_violation: DynamoDB.2
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.pat_main.arn
  }

  tags = {
    compliance_test = "intentional_violation"
    controls        = "DynamoDB.2"
  }
}

# =============================================================================
# 38. aws_efs_file_system.in_backup_plan
#     Policy: efs-in-backup-plan-policy.policy.hcl
#     Unknown because: backup plan association is cross-resource and post-apply
# =============================================================================

resource "aws_backup_vault" "test" {
  name        = "post-apply-backup-vault"
  kms_key_arn = aws_kms_key.pat_main.arn
}

resource "aws_backup_plan" "test" {
  name = "post-apply-backup-plan"

  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.test.name
    schedule          = "cron(0 5 ? * * *)"

    lifecycle {
      delete_after = 30
    }
  }
}

resource "aws_iam_role" "backup" {
  name = "post-apply-backup-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "backup.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_efs_file_system" "backup_pass" {
  encrypted  = true
  kms_key_id = aws_kms_key.pat_main.arn
}

# pass: EFS file system enrolled in a backup plan
resource "aws_backup_selection" "efs_pass" {
  name         = "post-apply-efs-backup"
  iam_role_arn = aws_iam_role.backup.arn
  plan_id      = aws_backup_plan.test.id

  resources = [aws_efs_file_system.backup_pass.arn]
}

# fail: EFS file system NOT in any backup plan
# intentional_violation: no aws_backup_selection referencing this file system
resource "aws_efs_file_system" "backup_fail" {
  encrypted  = true
  kms_key_id = aws_kms_key.pat_main.arn
  # No aws_backup_selection — intentional_violation: EFS.1

  tags = {
    compliance_test = "intentional_violation"
    controls        = "EFS.1"
  }
}

# =============================================================================
# 39. aws_redshiftserverless_workgroup.require_ssl_encryption
#     Policy: redshift-serverless-workgroup-encrypted-in-transit-policy.policy.hcl
#     Unknown because: config_parameter block is computed post-apply
# =============================================================================

resource "aws_redshiftserverless_namespace" "pass" {
  namespace_name      = "post-apply-rs-serverless-pass"
  admin_username      = "clusteradmin"
  admin_user_password = var.db_password
  kms_key_id          = aws_kms_key.pat_main.arn
}

# pass: require_ssl config parameter = true
resource "aws_redshiftserverless_workgroup" "pass" {
  namespace_name = aws_redshiftserverless_namespace.pass.namespace_name
  workgroup_name = "post-apply-rs-serverless-pass"
  base_capacity  = 8

  enhanced_vpc_routing = true
  publicly_accessible  = false
  subnet_ids           = aws_subnet.private[*].id
  security_group_ids   = [aws_security_group.redshift.id]

  config_parameter {
    parameter_key   = "require_ssl"
    parameter_value = "true" # satisfies require_ssl_encryption
  }
}

resource "aws_redshiftserverless_namespace" "ssl_fail" {
  namespace_name      = "post-apply-rs-serverless-ssl-fail"
  admin_username      = "clusteradmin"
  admin_user_password = var.db_password
}

# fail: require_ssl = false
# intentional_violation: require_ssl = false
resource "aws_redshiftserverless_workgroup" "ssl_fail" {
  namespace_name = aws_redshiftserverless_namespace.ssl_fail.namespace_name
  workgroup_name = "post-apply-rs-serverless-ssl-fail"
  base_capacity  = 8

  enhanced_vpc_routing = false
  publicly_accessible  = false
  subnet_ids           = aws_subnet.private[*].id
  security_group_ids   = [aws_security_group.redshift.id]

  config_parameter {
    parameter_key   = "require_ssl"
    parameter_value = "false" # intentional_violation
  }

  tags = {
    compliance_test = "intentional_violation"
    controls        = "RedshiftServerless.SSL"
  }
}

# =============================================================================
# 40. aws_ecs_service.no_public_ip
# 41. aws_ecs_service.fargate_latest_platform
#     Policies: ecs-service-assign-public-ip-disabled / ecs-fargate-latest-platform-version
#     Unknown because: network_configuration.assign_public_ip is computed post-apply
# =============================================================================

resource "aws_ecs_cluster" "test" {
  name = "post-apply-ecs-test"
}

resource "aws_iam_role" "ecs_task_execution" {
  name = "post-apply-ecs-task-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_ecs_task_definition" "test" {
  family                   = "post-apply-ecs-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn

  container_definitions = jsonencode([{
    name      = "app"
    image     = "public.ecr.aws/nginx/nginx:latest"
    essential = true
    user      = "1000"
    readonlyRootFilesystem = true
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/ecs/post-apply-test"
        "awslogs-region"        = data.aws_region.current.name
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])
}

resource "aws_security_group" "ecs" {
  name        = "post-apply-ecs"
  description = "ECS post-apply policy test"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# pass: private subnet, no public IP, LATEST Fargate platform
resource "aws_ecs_service" "pass" {
  name             = "post-apply-ecs-pass"
  cluster          = aws_ecs_cluster.test.id
  task_definition  = aws_ecs_task_definition.test.arn
  desired_count    = 1
  launch_type      = "FARGATE"
  platform_version = "LATEST" # satisfies ecs-fargate-latest-platform-version

  network_configuration {
    subnets          = [aws_subnet.private[0].id]
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false # satisfies ecs-service-assign-public-ip-disabled
  }
}

# fail: public IP, pinned old platform version
# intentional_violation: assign_public_ip=true, platform_version pinned
resource "aws_ecs_service" "public_fail" {
  name             = "post-apply-ecs-public-fail"
  cluster          = aws_ecs_cluster.test.id
  task_definition  = aws_ecs_task_definition.test.arn
  desired_count    = 1
  launch_type      = "FARGATE"
  platform_version = "1.4.0" # intentional_violation: ECS.FargatePlatform

  network_configuration {
    subnets          = [aws_subnet.private[0].id]
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = true # intentional_violation: ECS.2
  }

  tags = {
    compliance_test = "intentional_violation"
    controls        = "ECS.2,ECS.FargatePlatform"
  }
}

# =============================================================================
# 42. aws_datasync_task.logging_required
#     Policy: datasync-task-logging-enabled-policy.policy.hcl
#     Unknown because: cloudwatch_log_group_arn is a computed reference post-apply
# =============================================================================

resource "aws_s3_bucket" "datasync" {
  bucket        = "post-apply-datasync-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_iam_role" "datasync" {
  name = "post-apply-datasync-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "datasync.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "datasync" {
  role = aws_iam_role.datasync.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketMultipartUploads",
                  "s3:AbortMultipartUpload", "s3:DeleteObject", "s3:GetObject",
                  "s3:ListMultipartUploadParts", "s3:PutObject"]
      Resource = ["${aws_s3_bucket.datasync.arn}", "${aws_s3_bucket.datasync.arn}/*"]
    }]
  })
}

resource "aws_datasync_location_s3" "test" {
  s3_bucket_arn = aws_s3_bucket.datasync.arn
  subdirectory  = "/source"

  s3_config {
    bucket_access_role_arn = aws_iam_role.datasync.arn
  }
}

resource "aws_cloudwatch_log_group" "datasync" {
  name              = "/aws/datasync/post-apply-test"
  retention_in_days = 7
}

# pass: log_level = TRANSFER, cloudwatch_log_group_arn set
resource "aws_datasync_task" "pass" {
  source_location_arn      = aws_datasync_location_s3.test.arn
  destination_location_arn = aws_datasync_location_s3.test.arn
  cloudwatch_log_group_arn = "${aws_cloudwatch_log_group.datasync.arn}:*"

  options {
    log_level              = "TRANSFER"
    verify_mode            = "ONLY_FILES_TRANSFERRED"
    transfer_mode          = "CHANGED"
    posix_permissions      = "NONE"
    preserve_deleted_files = "REMOVE"
    uid                    = "NONE"
    gid                    = "NONE"
    overwrite_mode         = "ALWAYS"
    atime                  = "BEST_EFFORT"
    mtime                  = "PRESERVE"
    bytes_per_second       = -1
  }
}

# fail: log_level = OFF, no cloudwatch_log_group_arn
# intentional_violation: log_level = OFF, no log group
resource "aws_datasync_task" "logging_fail" {
  source_location_arn      = aws_datasync_location_s3.test.arn
  destination_location_arn = aws_datasync_location_s3.test.arn
  # cloudwatch_log_group_arn intentionally omitted

  options {
    log_level              = "OFF" # intentional_violation: DataSync.1
    verify_mode            = "ONLY_FILES_TRANSFERRED"
    transfer_mode          = "CHANGED"
    posix_permissions      = "NONE"
    preserve_deleted_files = "REMOVE"
    uid                    = "NONE"
    gid                    = "NONE"
    overwrite_mode         = "ALWAYS"
    atime                  = "BEST_EFFORT"
    mtime                  = "PRESERVE"
    bytes_per_second       = -1
  }

  tags = {
    compliance_test = "intentional_violation"
    controls        = "DataSync.1"
  }
}

# =============================================================================
# 43. aws_secretsmanager_secret.rotation_enabled_check
# 44. aws_secretsmanager_secret.rotation_success_check
#     Policies: secretsmanager-rotation-enabled-check / secretsmanager-scheduled-rotation-success-check
#     Unknown because: rotation_enabled and rotation_lambda_arn are computed post-apply
# =============================================================================

data "archive_file" "rotator" {
  type        = "zip"
  output_path = "${path.module}/rotator.zip"

  source {
    filename = "index.py"
    content  = <<-EOF
      import boto3, os
      def handler(event, context):
          pass
    EOF
  }
}

resource "aws_iam_role" "rotator" {
  name = "post-apply-secret-rotator"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "rotator" {
  role = aws_iam_role.rotator.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue",
                  "secretsmanager:PutSecretValue", "secretsmanager:UpdateSecretVersionStage"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_lambda_function" "rotator" {
  function_name    = "post-apply-secret-rotator"
  runtime          = "python3.12"
  handler          = "index.handler"
  role             = aws_iam_role.rotator.arn
  filename         = data.archive_file.rotator.output_path
  source_code_hash = data.archive_file.rotator.output_base64sha256
  timeout          = 30
}

resource "aws_lambda_permission" "rotator" {
  function_name  = aws_lambda_function.rotator.function_name
  action         = "lambda:InvokeFunction"
  principal      = "secretsmanager.amazonaws.com"
  source_account = data.aws_caller_identity.current.account_id
}

# pass: rotation enabled with schedule
resource "aws_secretsmanager_secret" "pass" {
  name                    = "post-apply/secret-pass"
  kms_key_id              = aws_kms_key.pat_main.arn
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_rotation" "pass" {
  secret_id           = aws_secretsmanager_secret.pass.id
  rotation_lambda_arn = aws_lambda_function.rotator.arn

  rotation_rules {
    schedule_expression = "rate(30 days)" # satisfies rotation_success_check
  }
}

# fail: no rotation configured
# intentional_violation: no aws_secretsmanager_secret_rotation resource
resource "aws_secretsmanager_secret" "no_rotation_fail" {
  name                    = "post-apply/secret-no-rotation-fail"
  kms_key_id              = aws_kms_key.pat_main.arn
  recovery_window_in_days = 7
  # no aws_secretsmanager_secret_rotation — intentional_violation: SecretsManager.1

  tags = {
    compliance_test = "intentional_violation"
    controls        = "SecretsManager.1"
  }
}

# =============================================================================
# 45. aws_iam_policy.deny_full_admin_privileges
# 46. aws_iam_policy.deny_service_wildcards
#     Policies: iam-policy-no-statements-with-admin-access /
#               iam-policy-no-statements-with-full-access
#     Unknown because: policy JSON document content is computed post-apply from jsonencode
# =============================================================================

# pass: scoped S3 read
resource "aws_iam_policy" "pass" {
  name = "post-apply-iam-pass"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "arn:aws:s3:::my-app-bucket/uploads/*"
    }]
  })
}

# fail: admin wildcard
# intentional_violation: Action=*, Resource=*
resource "aws_iam_policy" "admin_fail" {
  name = "post-apply-iam-admin-fail"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"   # intentional_violation: IAM.1
      Resource = "*"
    }]
  })

  tags = {
    compliance_test = "intentional_violation"
    controls        = "IAM.1"
  }
}

# fail: service wildcard (ec2:*)
# intentional_violation: Action=ec2:*
resource "aws_iam_policy" "service_wildcard_fail" {
  name = "post-apply-iam-service-wildcard-fail"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ec2:*"] # intentional_violation: IAM.21
      Resource = "*"
    }]
  })

  tags = {
    compliance_test = "intentional_violation"
    controls        = "IAM.21"
  }
}

# =============================================================================
# 47. aws_network_acl.no_unrestricted_ssh_rdp
# 48. aws_network_acl.unused_nacl_check
#     Policies: ec2-nacl-no-unrestricted-ssh-rdp / vpc-network-acl-unused-check
#     Unknown because: ingress rules and subnet_ids are computed post-apply
# =============================================================================

# pass: NACL with deny rules for SSH/RDP + associated to a subnet
resource "aws_network_acl" "pass" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [aws_subnet.private[0].id]
  tags       = { Name = "post-apply-nacl-pass" }
}

resource "aws_network_acl_rule" "pass_deny_ssh" {
  network_acl_id = aws_network_acl.pass.id
  rule_number    = 90
  protocol       = "tcp"
  rule_action    = "deny"
  egress         = false
  cidr_block     = "0.0.0.0/0"
  from_port      = 22
  to_port        = 22
}

resource "aws_network_acl_rule" "pass_deny_rdp" {
  network_acl_id = aws_network_acl.pass.id
  rule_number    = 91
  protocol       = "tcp"
  rule_action    = "deny"
  egress         = false
  cidr_block     = "0.0.0.0/0"
  from_port      = 3389
  to_port        = 3389
}

resource "aws_network_acl_rule" "pass_allow_https" {
  network_acl_id = aws_network_acl.pass.id
  rule_number    = 100
  protocol       = "tcp"
  rule_action    = "allow"
  egress         = false
  cidr_block     = "0.0.0.0/0"
  from_port      = 443
  to_port        = 443
}

resource "aws_network_acl_rule" "pass_egress_all" {
  network_acl_id = aws_network_acl.pass.id
  rule_number    = 100
  protocol       = "-1"
  rule_action    = "allow"
  egress         = true
  cidr_block     = "0.0.0.0/0"
}

# fail: no deny rules for SSH/RDP, no subnet association
# intentional_violation: no deny on 22/3389, subnet_ids = []
resource "aws_network_acl" "fail" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [] # intentional_violation: unused NACL (vpc-network-acl-unused-check)
  tags = {
    Name            = "post-apply-nacl-fail"
    compliance_test = "intentional_violation"
    controls        = "EC2.21,VPC.NACLUnused"
  }
}

resource "aws_network_acl_rule" "fail_allow_rdp" {
  network_acl_id = aws_network_acl.fail.id
  rule_number    = 100
  protocol       = "tcp"
  rule_action    = "allow" # intentional_violation: should deny port 3389
  egress         = false
  cidr_block     = "0.0.0.0/0"
  from_port      = 3389
  to_port        = 3389
}

# =============================================================================
# 49. aws_s3_bucket.ssl_required
# 50. aws_s3_bucket.s3_block_public_access
# 51. aws_s3_bucket.server_access_logging_enabled
# 52. aws_s3_bucket.lifecycle_policy_check
# 53. aws_s3_bucket_policy.s3-bucket-blacklisted-actions-prohibited
#     Unknown because: has_policy_resource lookup is a cross-resource reference post-apply
# =============================================================================

resource "aws_s3_bucket" "app_data_pass" {
  bucket        = "post-apply-s3-pass-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "app_data_pass" {
  bucket                  = aws_s3_bucket.app_data_pass.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "app_data_pass" {
  bucket = aws_s3_bucket.app_data_pass.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "app_data_pass" {
  depends_on = [aws_s3_bucket_versioning.app_data_pass]
  bucket     = aws_s3_bucket.app_data_pass.id

  rule {
    id     = "transition-expire"
    status = "Enabled"
    filter {}

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket" "logs_target" {
  bucket        = "post-apply-s3-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "logs_target" {
  bucket = aws_s3_bucket.logs_target.id
  rule { object_ownership = "BucketOwnerPreferred" }
}

resource "aws_s3_bucket_logging" "app_data_pass" {
  bucket        = aws_s3_bucket.app_data_pass.id
  target_bucket = aws_s3_bucket.logs_target.id
  target_prefix = "app-data/"
}

data "aws_iam_policy_document" "ssl_pass" {
  statement {
    sid     = "DenyNonSSL"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [aws_s3_bucket.app_data_pass.arn, "${aws_s3_bucket.app_data_pass.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "ssl_pass" {
  bucket     = aws_s3_bucket.app_data_pass.id
  policy     = data.aws_iam_policy_document.ssl_pass.json
  depends_on = [aws_s3_bucket_public_access_block.app_data_pass]
}

# fail: public access block disabled, no SSL policy, no lifecycle, no logging
resource "aws_s3_bucket" "app_data_fail" {
  bucket        = "post-apply-s3-fail-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    compliance_test = "intentional_violation"
    controls        = "S3.1,S3.2,S3.3,S3.5,S3.9,S3.13"
  }
}

resource "aws_s3_bucket_public_access_block" "app_data_fail" {
  bucket                  = aws_s3_bucket.app_data_fail.id
  block_public_acls       = false # intentional_violation
  block_public_policy     = false # intentional_violation
  ignore_public_acls      = false # intentional_violation
  restrict_public_buckets = false # intentional_violation
}

# =============================================================================
# 54. aws_glue_job.glue_spark_version_check
#     Policy: glue-spark-job-supported-version-policy.policy.hcl
#     Unknown because: command.name (is_spark_job) is computed post-apply
# =============================================================================

resource "aws_iam_role" "glue" {
  name = "post-apply-glue-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "glue.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "glue" {
  role       = aws_iam_role.glue.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}

# pass: current supported Glue version 4.0
resource "aws_glue_job" "pass" {
  name         = "post-apply-glue-pass"
  role_arn     = aws_iam_role.glue.arn
  glue_version = "4.0"

  command {
    name            = "glueetl"
    script_location = "s3://${aws_s3_bucket.app_data_pass.id}/glue-scripts/etl.py"
    python_version  = "3"
  }

  number_of_workers = 2
  worker_type       = "G.1X"
}

# fail: EOL Glue version 2.0
# intentional_violation: glue_version = 2.0
resource "aws_glue_job" "version_fail" {
  name         = "post-apply-glue-version-fail"
  role_arn     = aws_iam_role.glue.arn
  glue_version = "2.0" # intentional_violation: Glue.4

  command {
    name            = "glueetl"
    script_location = "s3://${aws_s3_bucket.app_data_pass.id}/glue-scripts/etl-fail.py"
    python_version  = "3"
  }

  number_of_workers = 2
  worker_type       = "G.1X"

  tags = {
    compliance_test = "intentional_violation"
    controls        = "Glue.4"
  }
}

# =============================================================================
# 55. aws_ssm_document.ssm_document_not_public
#     Policy: ssm-document-not-public-policy.policy.hcl
#     Unknown because: permissions.account_ids is inconsistently typed (string vs list) post-apply
# =============================================================================

resource "aws_ssm_document" "pass" {
  name            = "post-apply-ssm-pass"
  document_type   = "Command"
  document_format = "JSON"

  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Post-apply SSM document regression test"
    mainSteps = [{
      action = "aws:runShellScript"
      name   = "runScript"
      inputs = { runCommand = ["echo hello"] }
    }]
  })

  permissions = {
    type        = "Share"
    account_ids = "" # private
  }
}

resource "aws_ssm_document" "public_fail" {
  name            = "post-apply-ssm-public-fail"
  document_type   = "Command"
  document_format = "JSON"

  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Post-apply SSM public document — intentional_violation"
    mainSteps = [{
      action = "aws:runShellScript"
      name   = "runScript"
      inputs = { runCommand = ["echo hello"] }
    }]
  })

  permissions = {
    type        = "Share"
    account_ids = "All" # intentional_violation: SSM.4
  }

  tags = {
    compliance_test = "intentional_violation"
    controls        = "SSM.4"
  }
}

# =============================================================================
# 56. aws_autoscaling_group.use_launch_templates
# 57. aws_autoscaling_group.multiple_instance_types_and_azs
# 58. aws_launch_configuration.imdsv2_required
#     Policies: autoscaling-launch-template / autoscaling-multiple-instance-types /
#               autoscaling-launchconfig-requires-imdsv2
#     Unknown because: mixed_instances_policy and AZ count are computed post-apply
# =============================================================================

resource "aws_security_group" "asg" {
  name        = "post-apply-asg"
  description = "ASG post-apply policy test"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_launch_template" "asg_pass" {
  name          = "post-apply-asg-lt-pass"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = "t3.micro"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.asg.id]
  }
}

# pass: multi-AZ (3 subnets), launch template with mixed instances
resource "aws_autoscaling_group" "pass" {
  name                = "post-apply-asg-pass"
  min_size            = 1
  max_size            = 4
  desired_capacity    = 2
  vpc_zone_identifier = aws_subnet.private[*].id # 3 AZs

  mixed_instances_policy {
    launch_template {
      launch_template_specification {
        launch_template_id = aws_launch_template.asg_pass.id
        version            = "$Latest"
      }

      override {
        instance_type = "t3.micro"
      }

      override {
        instance_type = "t3.small"
      }
    }
  }

  tag {
    key                 = "Name"
    value               = "post-apply-asg-pass"
    propagate_at_launch = true
  }
}

# fail: single AZ, launch configuration (not template)
resource "aws_launch_configuration" "public_ip_fail" {
  name_prefix                 = "post-apply-lc-fail-"
  image_id                    = data.aws_ami.amazon_linux_2023.id
  instance_type               = "t3.micro"
  associate_public_ip_address = true # intentional_violation: AutoScaling.5
  security_groups             = [aws_security_group.asg.id]

  # metadata_options not supported on launch configurations — IMDSv2 cannot be enforced
  # intentional_violation: AutoScaling.LaunchConfigIMDSv2

  lifecycle { create_before_destroy = true }
}

resource "aws_autoscaling_group" "single_az_fail" {
  name                 = "post-apply-asg-single-az-fail"
  min_size             = 1
  max_size             = 2
  desired_capacity     = 1
  vpc_zone_identifier  = [aws_subnet.private[0].id] # intentional_violation: single AZ
  launch_configuration = aws_launch_configuration.public_ip_fail.name # intentional_violation: AutoScaling.9

  tag {
    key                 = "compliance_test"
    value               = "intentional_violation"
    propagate_at_launch = false
  }
}

# =============================================================================
# 59. aws_route53_zone.dns_query_logging_enabled
#     Policy: route53-query-logging-enabled-policy.policy.hcl
#     Unknown because: query_logging association is a cross-resource lookup post-apply
# =============================================================================

resource "aws_route53_zone" "pass" {
  name = "post-apply-pass.example.com"
}

resource "aws_cloudwatch_log_group" "dns" {
  provider          = aws.us_east_1
  name              = "/aws/route53/post-apply-pass.example.com"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_resource_policy" "route53" {
  provider    = aws.us_east_1
  policy_name = "post-apply-route53-query-logging"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "route53.amazonaws.com" }
      Action    = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource  = "arn:aws:logs:us-east-1:${data.aws_caller_identity.current.account_id}:log-group:/aws/route53/*:*"
    }]
  })
}

resource "aws_route53_query_log" "pass" {
  depends_on               = [aws_cloudwatch_log_resource_policy.route53]
  cloudwatch_log_group_arn = aws_cloudwatch_log_group.dns.arn
  zone_id                  = aws_route53_zone.pass.zone_id
}

# fail: public zone with no query logging
# intentional_violation: no aws_route53_query_log resource
resource "aws_route53_zone" "no_logging_fail" {
  name = "post-apply-fail.example.com"
  # aws_route53_query_log intentionally omitted — intentional_violation: Route53.2

  tags = {
    compliance_test = "intentional_violation"
    controls        = "Route53.2"
  }
}

# =============================================================================
# 60. aws_wafv2_rule_group.waf_rule_group_cloudwatch_metrics_enabled
#     Policy: wafv2-rulegroup-logging-enabled-policy.policy.hcl
#     Unknown because: rule visibility_config is computed post-apply
# =============================================================================

# pass: cloudwatch_metrics_enabled = true on rule group and each rule
resource "aws_wafv2_rule_group" "pass" {
  name     = "post-apply-waf-rg-pass"
  scope    = "REGIONAL"
  capacity = 10

  rule {
    name     = "block-bad-ips"
    priority = 1

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.test.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true # satisfies waf_rule_group_cloudwatch_metrics_enabled
      metric_name                = "block-bad-ips"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "post-apply-waf-rg-pass"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_ip_set" "test" {
  name               = "post-apply-ip-set"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = ["192.0.2.0/24"]
}

# fail: cloudwatch_metrics_enabled = false on rule
# intentional_violation: rule visibility_config.cloudwatch_metrics_enabled = false
resource "aws_wafv2_rule_group" "metrics_fail" {
  name     = "post-apply-waf-rg-metrics-fail"
  scope    = "REGIONAL"
  capacity = 10

  rule {
    name     = "block-bad-ips"
    priority = 1

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.test.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = false # intentional_violation: WAF.RuleGroupMetrics
      metric_name                = "block-bad-ips"
      sampled_requests_enabled   = false
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = false # intentional_violation
    metric_name                = "post-apply-waf-rg-metrics-fail"
    sampled_requests_enabled   = false
  }

  tags = {
    compliance_test = "intentional_violation"
    controls        = "WAF.RuleGroupCloudWatchMetrics"
  }
}

# =============================================================================
# Variables
# =============================================================================

variable "db_password" {
  description = "Master password for RDS/Redshift/DocumentDB resources"
  type        = string
  sensitive   = true
  default     = "ChangeMe2024"
}

variable "availability_zones" {
  description = "List of availability zones to use for multi-AZ resources"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}
