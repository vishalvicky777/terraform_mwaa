provider "aws" {
  # Configuration options
  region = "eu-west-1"
  profile = "dev"
  access_key = "${var.aws_access_key}"
  secret_key = "${var.aws_secret_key}"
  token = "${var.aws_session_token}"
  #shared_credentials_files = ["C:\\Users\\vishal.shah\\.aws\\credentials"]
}
output "access_key" {
  value = "${var.aws_access_key}"
}
output "secret_key" {
  value = "${var.aws_secret_key}"
}

resource "aws_s3_bucket" "s3_bucket" {
    bucket = "tf-s3-airflow-dags"
}
resource "aws_s3_bucket_acl" "bucket_acl" {
   bucket =  aws_s3_bucket.s3_bucket.id
   acl    = "private"
  }
resource "aws_s3_bucket_versioning" "bucket_ver" {
  bucket = aws_s3_bucket.s3_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}
resource "aws_s3_bucket_public_access_block" "block_public_access" {
    bucket = aws_s3_bucket.s3_bucket.id
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  
}
data "aws_iam_policy_document" "assume" {
    version = "2012-10-17"
    statement {
            effect = "Allow"
            principals {
                identifiers = [
                    "airflow-env.amazonaws.com",
                    "airflow.amazonaws.com"
                ]
                type = "Service"
            }
            actions= ["sts:AssumeRole"]
        }
}
data "aws_iam_policy_document" "base" {
  version = "2012-10-17"
  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["arn:aws:airflow:eu-west-1:079133960332:environment/tf_airflow*"]
    actions   = ["airflow:PublishMetrics"]
  }

  statement {
    sid    = ""
    effect = "Allow"

    resources = [
      "arn:aws:s3:::tf-s3-airflow-dags",
      "arn:aws:s3:::tf-s3-airflow-dags/*",
    ]

    actions = [
      "s3:GetObject*",
      "s3:GetBucket*",
      "s3:List*",
      "s3:Create*"
    ]
  }

  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["arn:aws:logs:eu-west-1:079133960332:log-group:airflow-tf_airflow*"]

    actions = [
      "logs:CreateLogStream",
      "logs:CreateLogGroup",
      "logs:PutLogEvents",
      "logs:GetLogEvents",
      "logs:GetLogRecord",
      "logs:GetLogGroupFields",
      "logs:GetQueryResults",
    ]
  }

  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["*"]
    actions   = ["logs:DescribeLogGroups"]
  }

  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["*"]
    actions   = ["cloudwatch:PutMetricData"]
  }

  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["arn:aws:sqs:eu-west-1:*:airflow-celery-*"]

    actions = [
      "sqs:ChangeMessageVisibility",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:GetQueueUrl",
      "sqs:ReceiveMessage",
      "sqs:SendMessage",
    ]
  }

  statement {
    sid           = ""
    effect        = "Allow"
    resources = ["arn:aws:kms:*:111122223333:key/*"]

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:GenerateDataKey*",
      "kms:Encrypt",
    ]

    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["sqs.eu-central-1.amazonaws.com"]
    }
  }
}
data "aws_iam_policy_document" "serviceassume"{
  statement {
    sid     = ""
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["airflow.amazonaws.com"]
    }
  }
}
data "aws_iam_policy_document" "servrole" {
 statement {
    sid       = ""
    effect    = "Allow"
    resources = ["arn:aws:logs:*:*:log-group:airflow-*:*"]

    actions = [
      "logs:CreateLogStream",
      "logs:CreateLogGroup",
      "logs:DescribeLogGroups",
    ]
  }

  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "ec2:AttachNetworkInterface",
      "ec2:CreateNetworkInterface",
      "ec2:CreateNetworkInterfacePermission",
      "ec2:DeleteNetworkInterface",
      "ec2:DeleteNetworkInterfacePermission",
      "ec2:DescribeDhcpOptions",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSubnets",
      "ec2:DescribeVpcEndpoints",
      "ec2:DescribeVpcs",
      "ec2:DetachNetworkInterface",
    ]
  }

  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["arn:aws:ec2:*:*:vpc-endpoint/*"]
    actions   = ["ec2:CreateVpcEndpoint"]

    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "aws:TagKeys"
      values   = ["AmazonMWAAManaged"]
    }
  }

  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["arn:aws:ec2:*:*:vpc-endpoint/*"]

    actions = [
      "ec2:ModifyVpcEndpoint",
      "ec2:DeleteVpcEndpoints",
    ]

    condition {
      test     = "Null"
      variable = "aws:ResourceTag/AmazonMWAAManaged"
      values   = ["false"]
    }
  }

  statement {
    sid    = ""
    effect = "Allow"

    resources = [
      "arn:aws:ec2:*:*:vpc/*",
      "arn:aws:ec2:*:*:security-group/*",
      "arn:aws:ec2:*:*:subnet/*",
    ]

    actions = [
      "ec2:CreateVpcEndpoint",
      "ec2:ModifyVpcEndpoint",
    ]
  }

  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["arn:aws:ec2:*:*:vpc-endpoint/*"]
    actions   = ["ec2:CreateTags"]

    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["CreateVpcEndpoint"]
    }

    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "aws:TagKeys"
      values   = ["AmazonMWAAManaged"]
    }
  }

  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["*"]
    actions   = ["cloudwatch:PutMetricData"]

    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["AWS/MWAA"]
    }
  }
}
data "aws_iam_policy_document" "this" {
  source_policy_documents = [
    data.aws_iam_policy_document.base.json,
    data.aws_iam_policy_document.servrole.json
  ]
}
resource "aws_iam_role" "Xrole" {
    name = "mwaa_assume_role"
    assume_role_policy = data.aws_iam_policy_document.assume.json
} 
resource "aws_iam_role_policy" "airflowpolicy" {
    name = "mwaa_policy"
    policy = data.aws_iam_policy_document.base.json
    role = aws_iam_role.Xrole.id

  
}
resource "aws_vpc" "vpc1"{
  cidr_block = "10.0.0.0/16"
    tags = {
      Name = "tf_airflow_vpc"
    }
}
resource "aws_subnet" "tf_airflow_subnet1_public" {
  vpc_id = aws_vpc.vpc1.id
  cidr_block = "10.0.1.0/24"
  
    tags = {
      Name = "tf_airflow_subnet1_public"
    }
      availability_zone = "eu-west-1b"
}
resource "aws_subnet" "tf_airflow_subnet1_private" {
  vpc_id = aws_vpc.vpc1.id
  cidr_block = "10.0.10.0/24"
  
    tags = {
      Name = "tf_airflow_subnet1_private"
    }
      availability_zone = "eu-west-1b"
}
resource "aws_subnet" "tf_airflow_subnet2_public" {
  vpc_id = aws_vpc.vpc1.id
  cidr_block = "10.0.2.0/24"
  
    tags = {
      Name = "tf_airflow_subnet2_public"
    }
      availability_zone = "eu-west-1a"
}

resource "aws_subnet" "tf_airflow_subnet2_private" {
  vpc_id = aws_vpc.vpc1.id
  cidr_block = "10.0.11.0/24"
  
    tags = {
      Name = "tf_airflow_subnet2_private"
    }
      availability_zone = "eu-west-1a"
}
resource "aws_eip" "eip1" {
    vpc = true
  
}
resource "aws_eip" "eip2" {
    vpc = true
  
}
resource "aws_nat_gateway" "natgw1" {
  allocation_id = aws_eip.eip1.id
  subnet_id = aws_subnet.tf_airflow_subnet1_public.id
  depends_on = [
    aws_internet_gateway.igw
  ]
}
resource "aws_nat_gateway" "natgw2" {
  allocation_id = aws_eip.eip2.id
  subnet_id = aws_subnet.tf_airflow_subnet2_public.id
  depends_on = [
    aws_internet_gateway.igw
  ]

}
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc1.id
}
resource "aws_network_interface" "ninf1" {
  subnet_id = aws_subnet.tf_airflow_subnet1_public.id
  private_ip = "10.0.1.50"
  security_groups = [aws_security_group.allow_internal_traffic.id]
}
resource "aws_network_interface" "ninf2" {
  subnet_id = aws_subnet.tf_airflow_subnet2_public.id
  private_ip = "10.0.10.50"
  security_groups = [aws_security_group.allow_internal_traffic.id]
}
resource "aws_route_table" "routetable1" {
  vpc_id = aws_vpc.vpc1.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
 } 
 tags = {Name = "rt_igw"}
}
resource "aws_route_table_association" "routetableassoc1_public" {
  route_table_id = aws_route_table.routetable1.id
  subnet_id = aws_subnet.tf_airflow_subnet1_public.id
}
resource "aws_route_table_association" "routetableassoc2_public" {
  route_table_id = aws_route_table.routetable1.id
  subnet_id = aws_subnet.tf_airflow_subnet2_public.id
}
resource "aws_route_table" "routetable2" {
  vpc_id = aws_vpc.vpc1.id
  route{

    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.natgw1.id
    
  }
  tags = {Name = "rt_gw1"}
}
resource "aws_route_table_association" "routetableassoc2_private" {
    route_table_id = aws_route_table.routetable2.id
    subnet_id = aws_subnet.tf_airflow_subnet1_private.id  
    
}
resource "aws_route_table" "routetable3" {
  vpc_id = aws_vpc.vpc1.id
  route{

    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.natgw2.id
    
  }
  tags = {Name = "rt_gw2"}
}
resource "aws_route_table_association" "routetableassoc3_private" {
    route_table_id = aws_route_table.routetable3.id
    subnet_id = aws_subnet.tf_airflow_subnet2_private.id  
}  
resource "aws_security_group" "allow_internal_traffic" {
  name        = "allow_internal"
  vpc_id      = aws_vpc.vpc1.id

  ingress {
    description      = "TLS from VPC"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    self = true
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "airflow_traffic"
  }
}
resource "aws_mwaa_environment" "tf_airflow_mwaa" {
  dag_s3_path        = "dags/"
  execution_role_arn = aws_iam_role.Xrole.arn
  name               = "tf_airflow_dev"

  network_configuration {
    security_group_ids = [aws_security_group.allow_internal_traffic.id]
    subnet_ids         = [aws_subnet.tf_airflow_subnet1_private.id, aws_subnet.tf_airflow_subnet2_private.id]
    #subnet_ids = [aws_subnet.tf_airflow_subnet1_public.id, aws_subnet.tf_airflow_subnet2_public.id]
  }

  source_bucket_arn = aws_s3_bucket.s3_bucket.arn
  webserver_access_mode = "PUBLIC_ONLY"
  min_workers = 1
  max_workers = 2
  airflow_version = "2.4.3"
  #configure email client

  airflow_configuration_options = {
    "core.default_task_retries" = 3
    "core.parallelism" = 120
    "core.max_queued_runs_per_dag" = 2
    
    "webserver.expose_config" = "True"
    "scheduler.min_file_process_interval" = "300"

  }
}  