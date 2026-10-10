# fixtures/terraform/main.tf
#
# Intentionally-misconfigured sample infrastructure used to demonstrate
# GuardDeploy's scanning and ISO 27001 evidence mapping. Do not deploy
# this configuration to a real AWS account.

provider "aws" {
  region = "eu-west-2"
}

# --- Misconfiguration 1: public S3 bucket, no encryption, no logging ---
resource "aws_s3_bucket" "reports" {
  bucket = "guarddeploy-demo-reports-bucket"
}

resource "aws_s3_bucket_acl" "reports_acl" {
  bucket = aws_s3_bucket.reports.id
  acl    = "public-read"
}

# --- Misconfiguration 2: security group open to the world on SSH/RDP ---
resource "aws_security_group" "web" {
  name        = "guarddeploy-demo-web-sg"
  description = "Web tier security group"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
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

# --- Misconfiguration 3: unencrypted, publicly accessible RDS instance ---
resource "aws_db_instance" "app_db" {
  identifier           = "guarddeploy-demo-db"
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "appadmin"
  password             = "ChangeMe123!" # pragma: allowlist secret
  publicly_accessible  = true
  storage_encrypted    = false
  skip_final_snapshot  = true
}

# --- Misconfiguration 4: overly permissive IAM policy ---
resource "aws_iam_policy" "admin_everything" {
  name        = "guarddeploy-demo-admin-policy"
  description = "Overly broad policy — flagged by GuardDeploy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# --- Misconfiguration 5: EC2 instance with IMDSv1 permitted ---
resource "aws_instance" "app_server" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens = "optional" # should be "required" to force IMDSv2
  }

  monitoring = false
}
