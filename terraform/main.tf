resource "azurerm_resource_group" "lab" {
  name     = var.resource_group_name
  location = var.location
}
resource "azurerm_virtual_network" "lab" {
  name                = "VNET-Security-Lab-WestUS2"
  location            = var.location
  resource_group_name = var.resource_group_name
  address_space       = ["10.0.0.0/16"]
  tags = {
    Environment = "Lab"
    Owner       = "Yekta"
    Project     = "Azure Security"
    Purpose     = "Sentinel-Training"
  }
}
resource "azurerm_subnet" "security" {
  name                 = "Security-Subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = ["10.0.1.0/24"]
}


resource "azurerm_network_security_group" "vm" {
  name                = "NSG-Security-VM-01"
  location            = var.location
  resource_group_name = var.resource_group_name

  security_rule {
    name                       = "Allow-RDP-MyIP"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = var.admin_source_ip
    destination_address_prefix = "*"
  }

  tags = {
    Environment = "Lab"
    Owner       = "Yekta"
    Project     = "Azure Security"
    Purpose     = "Sentinel-Training"
    Reviewed    = "2026-08"
  }
}
resource "azurerm_log_analytics_workspace" "lab" {
  name                = "LAW-Security-Lab"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}


resource "azurerm_public_ip" "vm" {
  name                = "vm-sec-lab-01-ip"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"
  ip_version          = "IPv4"

  tags = {
    Environment = "Lab"
    Owner       = "Yekta"
    Project     = "Azure Security"
    Purpose     = "Sentinel-Training"
  }
}


resource "azurerm_network_interface" "vm" {
  name                = "vm-sec-lab-01932"
  location            = var.location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.security.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm.id
  }

  tags = {
    Environment = "Lab"
    Owner       = "Yekta"
    Project     = "Azure Security"
    Purpose     = "Sentinel-Training"
  }
}

resource "azurerm_network_interface_security_group_association" "vm" {
  network_interface_id      = azurerm_network_interface.vm.id
  network_security_group_id = azurerm_network_security_group.vm.id
}

resource "azurerm_windows_virtual_machine" "lab" {
  name                = "vm-sec-lab-01"
  computer_name       = "vm-sec-lab-01"
  location            = var.location
  resource_group_name = var.resource_group_name
  size                = "Standard_B2as_v2"
  admin_username      = "azureuser"
  admin_password      = var.vm_admin_password

  network_interface_ids      = [azurerm_network_interface.vm.id]
  secure_boot_enabled        = true
  vtpm_enabled               = true
  encryption_at_host_enabled = false
  patch_mode                 = "AutomaticByPlatform"
  patch_assessment_mode      = "AutomaticByPlatform"
  reboot_setting             = "IfRequired"

  os_disk {
    name                 = "vm-sec-lab-01_OsDisk_1_d41e959813f64f1fb23ac788d724ac35"
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
    disk_size_gb         = 127
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2025-datacenter-azure-edition"
    version   = "latest"
  }
  identity {
    type = "SystemAssigned"
  }
  boot_diagnostics {}
  tags = {
    Environment = "Lab"
    Owner       = "Yekta"
    Project     = "Azure Security"
    Purpose     = "Sentinel-Training"
  }
  additional_capabilities {
    hibernation_enabled = false
    ultra_ssd_enabled   = false
  }
  lifecycle {
    ignore_changes = [admin_password,
      vm_agent_platform_updates_enabled,


    ]
  }
}

resource "azurerm_public_ip" "linux" {
  name                = "vm-lnx-lab-01-ip"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = {
    Environment = "Lab"
    Owner       = "Yekta"
    Project     = "Azure Security"
    Purpose     = "Linux-Hardening"
  }
}
resource "azurerm_network_security_group" "linux" {
  name                = "NSG-Security-LNX-01"
  location            = var.location
  resource_group_name = var.resource_group_name

  security_rule {
    name                       = "Allow-SSH-AdminIP"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.admin_source_ip
    destination_address_prefix = "*"
  }

  tags = {
    Environment = "Lab"
    Owner       = "Yekta"
    Project     = "Azure Security"
    Purpose     = "Linux-Hardening"
  }
}
resource "azurerm_network_interface" "linux" {
  name                = "vm-lnx-lab-01-nic"
  location            = var.location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.security.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.linux.id
  }

  tags = {
    Environment = "Lab"
    Owner       = "Yekta"
    Project     = "Azure Security"
    Purpose     = "Linux-Hardening"
  }
}
resource "azurerm_network_interface_security_group_association" "linux" {
  network_interface_id      = azurerm_network_interface.linux.id
  network_security_group_id = azurerm_network_security_group.linux.id
}
resource "azurerm_linux_virtual_machine" "lab" {
  name                = "vm-lnx-lab-01"
  computer_name       = "vm-lnx-lab-01"
  location            = var.location
  resource_group_name = var.resource_group_name
  size                = "Standard_B1s"
  admin_username      = var.linux_admin_username

  network_interface_ids = [azurerm_network_interface.linux.id]

  disable_password_authentication = true

  admin_ssh_key {
    username   = var.linux_admin_username
    public_key = var.linux_ssh_public_key
  }

  os_disk {
    name                 = "vm-lnx-lab-01-osdisk"
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  identity {
    type = "SystemAssigned"
  }

  boot_diagnostics {}

  tags = {
    Environment = "Lab"
    Owner       = "Yekta"
    Project     = "Azure Security"
    Purpose     = "Linux-Hardening"
  }
}