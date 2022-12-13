# -*- coding: utf-8 -*-
import pydbus

import arpSender_constants
    
def pydbusProcessDescriptorString(descriptorString):
    bus = pydbus.SystemBus()
    _ORGANIZE_DBUS_NAME = arpSender_constants._ORGANIZE_DBUS_NAME
    _ORGANIZE_DBUS_PATH = arpSender_constants._ORGANIZE_DBUS_PATH
    organize = bus.get(_ORGANIZE_DBUS_NAME, _ORGANIZE_DBUS_PATH)
    x = organize.process_descriptor_string(descriptorString)
    print(x)

def pydbusGetLatestDescriptor():
    bus = pydbus.SystemBus()
    _ORGANIZE_DBUS_NAME = arpSender_constants._ORGANIZE_DBUS_NAME
    _ORGANIZE_DBUS_PATH = arpSender_constants._ORGANIZE_DBUS_PATH
    organize = bus.get(_ORGANIZE_DBUS_NAME, _ORGANIZE_DBUS_PATH)
    x = organize.our_latest_descriptors()
    return x
    