# Meridian Systems Infrastructure - Main Configuration
# Maintainer: platform-eng@internal.company.com
#
# WARNING: This configuration contains intentional security misconfigurations
# that were flagged during the last audit. The remediation is tracked in
# JIRA ticket INFRA-4521 but has not been prioritized yet.

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.30"
    }
  }

  backend "s3" {
    bucket         = "meridian-terraform-state"
    key            = "prod/main.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-locks"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Environment = "production"
      ManagedBy   = "terraform"
      Team        = "platform-engineering"
    }
  }
}

variable "aws_region" {
  description = "AWS region for resource deployment"
  type        = string
  default     = "us-east-1"
}

variable "db_password" {
  description = "RDS master password"
  type        = string
  sensitive   = true
}

# INSECURE: This S3 bucket has public read access enabled.
# Any object stored here is accessible to the entire internet.
# This was originally set up for a static website but the bucket also
# contains internal reports that were accidentally uploaded.
resource "aws_s3_bucket" "data_export" {
  bucket = "meridian-data-export-prod"

  tags = {
    Name    = "Data Export Bucket"
    Purpose = "Customer data exports and internal reports"
  }
}

resource "aws_s3_bucket_acl" "data_export_acl" {
  bucket = aws_s3_bucket.data_export.id
  acl    = "public-read"
}

resource "aws_s3_bucket_versioning" "data_export_versioning" {
  bucket = aws_s3_bucket.data_export.id

  versioning_configuration {
    status = "Suspended"
  }
}

# A second bucket configured correctly for comparison
resource "aws_s3_bucket" "application_logs" {
  bucket = "meridian-application-logs-prod"

  tags = {
    Name    = "Application Logs"
    Purpose = "Centralized application log storage"
  }
}

resource "aws_s3_bucket_acl" "application_logs_acl" {
  bucket = aws_s3_bucket.application_logs.id
  acl    = "private"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs_encryption" {
  bucket = aws_s3_bucket.application_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.logs_key.arn
    }
  }
}

resource "aws_kms_key" "logs_key" {
  description             = "KMS key for application logs encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

# VPC configuration
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "meridian-prod-vpc"
  }
}

resource "aws_subnet" "public_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "${var.aws_region}a"

  tags = {
    Name = "meridian-prod-public-a"
    Tier = "public"
  }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = "${var.aws_region}a"

  tags = {
    Name = "meridian-prod-private-a"
    Tier = "private"
  }
}

# INSECURE: This security group allows SSH access from any IP address.
# This was added as a temporary measure during an incident and was never
# reverted. It should be restricted to the VPN CIDR (10.100.0.0/16).
resource "aws_security_group" "bastion" {
  name        = "meridian-bastion-sg"
  description = "Security group for bastion host"
  vpc_id      = aws_vpc.main.id

  # Open SSH to the world. This is a critical security finding.
  ingress {
    description = "SSH from anywhere (SHOULD BE VPN ONLY)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "meridian-bastion-sg"
  }
}

# A properly configured security group for the application tier
resource "aws_security_group" "application" {
  name        = "meridian-application-sg"
  description = "Security group for application servers"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from load balancer"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  ingress {
    description = "HTTP from load balancer"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "meridian-application-sg"
  }
}

# INSECURE: This RDS instance does not have storage encryption enabled.
# Data at rest is stored in plaintext on the underlying EBS volumes.
# This violates the company's data protection policy and SOC2 requirements.
resource "aws_db_instance" "main" {
  identifier     = "meridian-prod-db"
  engine         = "postgres"
  engine_version = "16.1"
  instance_class = "db.r6g.xlarge"

  allocated_storage     = 500
  max_allocated_storage = 1000

  db_name  = "platform"
  username = "admin"
  password = var.db_password

  # Storage encryption is disabled. This is a compliance violation.
  storage_encrypted = false

  multi_az               = true
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.database.id]

  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "Mon:04:00-Mon:05:00"

  deletion_protection = true
  skip_final_snapshot = false

  final_snapshot_identifier = "meridian-prod-db-final-snapshot"

  tags = {
    Name = "meridian-prod-database"
  }
}

resource "aws_db_subnet_group" "main" {
  name       = "meridian-prod-db-subnet-group"
  subnet_ids = [aws_subnet.private_a.id]

  tags = {
    Name = "meridian-prod-db-subnet-group"
  }
}

resource "aws_security_group" "database" {
  name        = "meridian-database-sg"
  description = "Security group for RDS database"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "PostgreSQL from application tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.application.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "meridian-database-sg"
  }
}

output "data_export_bucket_arn" {
  description = "ARN of the data export S3 bucket"
  value       = aws_s3_bucket.data_export.arn
}

output "rds_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.main.endpoint
}
