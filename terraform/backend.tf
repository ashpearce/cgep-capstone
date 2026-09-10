terraform {
  backend "s3" {
    bucket  = "acme-health-intake-tfstate-8e35a7ab"
    key     = "capstone/terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
  }
}