################################################################################
#
# Xilinx Linux Character Chraracter DMA Driver
#
################################################################################

XLNX_DMA_DRV_VERSION = 1.0
XLNX_DMA_DRV_SITE = path_to_driver's_source_folder
XLNX_DMA_DRV_SITE_METHOD = local
XLNX_DMA_DRV_DEPENDENCIES = linux

define XLNX_DMA_DRV_BUILD_CMDS
	$(MAKE) $(LINUX_MAKE_FLAGS) CC=$(TARGET_CC) -C $(@D) KERNELDIR=$(LINUX_DIR) modules
endef

define XLNX_DMA_DRV_INSTALL_TARGET_CMDS
	$(MAKE) $(LINUX_MAKE_FLAGS) CC=$(TARGET_CC) -C $(@D) KERNELDIR=$(LINUX_DIR) modules_install
endef

$(eval $(kernel-module))
$(eval $(generic-package))
