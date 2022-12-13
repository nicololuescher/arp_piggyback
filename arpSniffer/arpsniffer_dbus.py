# -*- coding: utf-8 -*-
import pydbus

import arpsniffer_constants
    
def pydbusProcessDescriptorString(descriptorString):
    bus = pydbus.SystemBus()
    organize = bus.get(arpsniffer_constants._DISCOVER_DBUS_NAME, arpsniffer_constants._ORGANIZE_DBUS_PATH)
    x = organize.process_descriptor_string(descriptorString)
    print(x)

def pydbusGetLatestDescriptor():
    bus = pydbus.SystemBus()
    organize = bus.get(arpsniffer_constants._DISCOVER_DBUS_NAME, arpsniffer_constants._ORGANIZE_DBUS_PATH)
    x = organize.our_latest_descriptors()
    print(x)
    