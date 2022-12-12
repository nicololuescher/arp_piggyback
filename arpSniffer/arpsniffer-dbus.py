# -*- coding: utf-8 -*-
import pydbus

from arpsniffer-constants import (
    _ORGANIZE _DBUS _NAME,
    _ORGANIZE_DBUS_PATH)
    
def pydbusProcessDescriptorString(descriptorString):
    bus = pydbus.SystemBus()
    organize = bus.get(_ORGANIZE _DBUS _NAME, _ORGANIZE_DBUS_PATH)
    x = organize.process_descriptor_string(descriptorString)
    print(x)

def pydbusGetLatestDescriptor():
    bus = pydbus.SystemBus()
    organize = bus.get(_ORGANIZE _DBUS _NAME, _ORGANIZE_DBUS_PATH)
    x = organize.our_latest_descriptors()
    print(x)
    