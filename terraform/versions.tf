terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.80"
    }
  }
  backend "azurerm" {
    resource_group_name  = "RG-Security-Lab-WestUS2"
    storage_account_name = "stseclabtfstate"
    container_name       = "tfstate"
    key                  = "security-lab.tfstate"
    use_azuread_auth     = true
  }

}