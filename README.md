Xilinx linux dma driver sample
--------------------------

[![Build Status][travis-badge]][travis-link]

[travis-badge]:    https://travis-ci.org/pashinov/xilinx-dma-driver.svg?branch=master
[travis-link]:     https://travis-ci.org/pashinov/xilinx-dma-driver

Template for Xilinx linux dma driver

To build the driver:
```
$ make
```

To install the driver (if driver includes into device tree):
```
$ modprobe xlnx-dna-drv
```

The 'buildroot' folder contains Makefiles for building driver with buildroot system
