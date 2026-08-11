variable "subscription_id" {
  type        = string
  description = "Azure subscription ID for the security lab"
}

variable "location" {
  type        = string
  description = "Azure region for all lab resources"
  default     = "westus2"
}


variable "resource_group_name" {
  type        = string
  description = "Name of the resource group holding all lab resources"
  default     = "RG-Security-Lab-WestUS2"
}
variable "admin_source_ip" {
  type        = string
  description = "Source IP allowed to reach RDP on the lab VM"
}
variable "vm_admin_password" {
  type      = string
  sensitive = true
}


variable "linux_admin_username" {
  type        = string
  description = "Admin username for the Linux lab VM"
  default     = "azureadmin"
}

variable "linux_ssh_public_key" {
  type        = string
  description = "SSH public key authorised for the Linux lab VM admin user"
}