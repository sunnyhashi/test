################################################################################
# TRIGGER: azure/linux-vm-boot-diagnostics-enabled
# Policy:  Checks that Linux virtual machines have boot diagnostics enabled.
#
# TRIGGER: boot_diagnostics is intentionally omitted from the VM.
################################################################################

resource "azurerm_virtual_network" "vm" {
  name                = "azure-vm-vnet"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  address_space       = ["10.20.0.0/16"]
}

resource "azurerm_subnet" "vm" {
  name                 = "default"
  resource_group_name  = azurerm_resource_group.test.name
  virtual_network_name = azurerm_virtual_network.vm.name
  address_prefixes     = ["10.20.1.0/24"]
}

resource "azurerm_network_interface" "vm" {
  name                = "azure-vm-nic"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.vm.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "no_boot_diagnostics" {
  name                = "azure-vm-no-boot-diagnostics"
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  size                = "Standard_B1s"
  admin_username      = "azureuser"
  network_interface_ids = [
    azurerm_network_interface.vm.id
  ]

  disable_password_authentication = true

  admin_ssh_key {
    username   = "azureuser"
    public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0oLhpV06AjnAITRVjVyN6iqoSTQep1YE4zHlcmivVuSZBC1WKbofwy4nStDcSP0XK/b8QR7D8TFvBrENKTQf5IF/WTlDX4f0MWUXCtOcD5I4580FN7TPOB9i7zUyROh1TBhBW6DNuuVXxqSSCbXzNK1epSKjnHd7DSl+WNux5JmZD+7h623DLNaDiv7O19GyLIPQit8RBpRa8dTDqXTWySmOkI3O3yZbTbihvx0v5vSfALjbf0smypK40vziRl4R24gwb8aXwUALHj16l8HcCAi1kBdfQ3WHI6jSYklt2mXmcngSOcs+0Um5kZd3JX7b+jJ2LiIvZT1zVstic3Cbl"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts"
    version   = "latest"
  }

  # boot_diagnostics intentionally omitted
}
