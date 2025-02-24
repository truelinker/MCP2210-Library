/*******************************************************
 HIDAPI - Multi-Platform library for
 communication with HID devices.

 Alan Ott
 Signal 11 Software

 8/22/2009
 Windows Version - 6/2/2009

 Copyright 2009, All Rights Reserved.
 
 At the discretion of the user of this library,
 this software may be licensed under the terms of the
 GNU Public License v3, a BSD-Style license, or the
 original HIDAPI license as outlined in the LICENSE.txt,
 LICENSE-gpl3.txt, LICENSE-bsd.txt, and LICENSE-orig.txt
 files located at the root of the source distribution.
 These files may also be found in the public source
 code repository located at:
        http://github.com/signal11/hidapi .
********************************************************/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "hidapi.h"
#include <setupapi.h>

// Define necessary HID structures and constants
#define DIGCF_PRESENT          0x00000002
#define DIGCF_DEVICEINTERFACE  0x00000010

// Define HID-specific types if not available
typedef VOID* PHIDP_PREPARSED_DATA;
typedef USHORT USAGE;
typedef struct _HIDP_CAPS
{
    USAGE    Usage;
    USAGE    UsagePage;
    USHORT   InputReportByteLength;
    USHORT   OutputReportByteLength;
    USHORT   FeatureReportByteLength;
    USHORT   Reserved[17];
    USHORT   NumberLinkCollectionNodes;
    USHORT   NumberInputButtonCaps;
    USHORT   NumberInputValueCaps;
    USHORT   NumberInputDataIndices;
    USHORT   NumberOutputButtonCaps;
    USHORT   NumberOutputValueCaps;
    USHORT   NumberOutputDataIndices;
    USHORT   NumberFeatureButtonCaps;
    USHORT   NumberFeatureValueCaps;
    USHORT   NumberFeatureDataIndices;
} HIDP_CAPS, *PHIDP_CAPS;

typedef struct _HIDD_ATTRIBUTES {
    ULONG Size;
    USHORT VendorID;
    USHORT ProductID;
    USHORT VersionNumber;
} HIDD_ATTRIBUTES, *PHIDD_ATTRIBUTES;

// Define HID status values
#define HIDP_STATUS_SUCCESS 0x00110000

// Function prototypes
typedef BOOLEAN (__stdcall *HidD_GetAttributes_)(HANDLE HidDeviceObject, PHIDD_ATTRIBUTES Attributes);
typedef BOOLEAN (__stdcall *HidD_GetPreparsedData_)(HANDLE HidDeviceObject, PHIDP_PREPARSED_DATA *PreparsedData);
typedef BOOLEAN (__stdcall *HidD_FreePreparsedData_)(PHIDP_PREPARSED_DATA PreparsedData);
typedef LONG (__stdcall *HidP_GetCaps_)(PHIDP_PREPARSED_DATA PreparsedData, PHIDP_CAPS Capabilities);

// Global variables for function pointers
static HidD_GetAttributes_ HidD_GetAttributes;
static HidD_GetPreparsedData_ HidD_GetPreparsedData;
static HidD_FreePreparsedData_ HidD_FreePreparsedData;
static HidP_GetCaps_ HidP_GetCaps;
static HMODULE hHID = NULL;

struct hid_device_ {
	HANDLE handle;
	int blocking;
};

static void load_hid_functions(void) {
	if (!hHID) {
		hHID = LoadLibrary("hid.dll");
		if (hHID) {
			HidD_GetAttributes = (HidD_GetAttributes_)GetProcAddress(hHID, "HidD_GetAttributes");
			HidD_GetPreparsedData = (HidD_GetPreparsedData_)GetProcAddress(hHID, "HidD_GetPreparsedData");
			HidD_FreePreparsedData = (HidD_FreePreparsedData_)GetProcAddress(hHID, "HidD_FreePreparsedData");
			HidP_GetCaps = (HidP_GetCaps_)GetProcAddress(hHID, "HidP_GetCaps");
		}
	}
}

hid_device *new_hid_device() {
	load_hid_functions();
	if (!HidD_GetAttributes) {
		printf("Failed to load HID functions\n");
		return NULL;
	}
	
	hid_device *dev = calloc(1, sizeof(hid_device));
	if (!dev) {
		printf("Failed to allocate device structure\n");
		return NULL;
	}
	
	dev->handle = INVALID_HANDLE_VALUE;
	dev->blocking = 1;
	return dev;
}

int HID_API_EXPORT HID_API_CALL hid_init(void) { return 0; }
int HID_API_EXPORT HID_API_CALL hid_exit(void) { return 0; }

// Add this GUID definition at the top with other constants
static const GUID GUID_DEVINTERFACE_HID = 
    {0x4d1e55b2, 0xf16f, 0x11cf, {0x88, 0xcb, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30}};

hid_device * HID_API_EXPORT HID_API_CALL hid_open(unsigned short vendor_id, unsigned short product_id, const wchar_t *serial_number) {
    GUID interface_class_guid = {0x4d1e55b2, 0xf16f, 0x11cf, {0x88, 0xcb, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30}};
    HDEVINFO device_info_set;
    SP_DEVICE_INTERFACE_DATA device_interface_data;
    PSP_DEVICE_INTERFACE_DETAIL_DATA detail_data = NULL;
    int device_index = 0;
    DWORD required_size = 0;
    BOOL found = FALSE;
    hid_device *dev = NULL;

    // Get the device info set
    device_info_set = SetupDiGetClassDevs(&interface_class_guid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (device_info_set == INVALID_HANDLE_VALUE) {
        printf("SetupDiGetClassDevs failed\n");
        return NULL;
    }

    dev = new_hid_device();
    if (!dev) {
        SetupDiDestroyDeviceInfoList(device_info_set);
        return NULL;
    }

    device_interface_data.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    while (SetupDiEnumDeviceInterfaces(device_info_set, NULL, &interface_class_guid, device_index, &device_interface_data)) {
        DWORD required_size = 0;
        
        SetupDiGetDeviceInterfaceDetail(device_info_set, &device_interface_data, NULL, 0, &required_size, NULL);
        detail_data = (PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc(required_size);
        detail_data->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

        if (SetupDiGetDeviceInterfaceDetail(device_info_set, &device_interface_data, detail_data, required_size, NULL, NULL)) {
            // Open with non-overlapped I/O
            dev->handle = CreateFile(detail_data->DevicePath,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                OPEN_EXISTING,
                0,
                NULL);

            if (dev->handle != INVALID_HANDLE_VALUE) {
                HIDD_ATTRIBUTES attrib;
                attrib.Size = sizeof(HIDD_ATTRIBUTES);
                
                if (HidD_GetAttributes && HidD_GetAttributes(dev->handle, &attrib)) {
                    if (attrib.VendorID == vendor_id && attrib.ProductID == product_id) {
                        // Get capabilities
                        PHIDP_PREPARSED_DATA pp_data = NULL;
                        if (HidD_GetPreparsedData && HidD_GetPreparsedData(dev->handle, &pp_data)) {
                            HIDP_CAPS caps;
                            if (HidP_GetCaps && HidP_GetCaps(pp_data, &caps) == HIDP_STATUS_SUCCESS) {
                                // Store capabilities if needed
                                HidD_FreePreparsedData(pp_data);
                                found = TRUE;
                                break;
                            }
                            HidD_FreePreparsedData(pp_data);
                        }
                    }
                }
                CloseHandle(dev->handle);
                dev->handle = INVALID_HANDLE_VALUE;
            }
        }
        free(detail_data);
        device_index++;
    }

    SetupDiDestroyDeviceInfoList(device_info_set);

    if (!found) {
        free(dev);
        return NULL;
    }

    return dev;
}

void HID_API_EXPORT HID_API_CALL hid_close(hid_device *dev) {
	if (!dev) return;
	CloseHandle(dev->handle);
	free(dev);
	if (hHID) {
		FreeLibrary(hHID);
		hHID = NULL;
	}
}

int HID_API_EXPORT HID_API_CALL hid_write(hid_device *dev, const unsigned char *data, size_t length) {
    DWORD bytes_written;
    BOOL res;
    unsigned char *buf;

    if (!dev->handle || length == 0)
        return -1;

    // Add report ID
    buf = (unsigned char *)malloc(length + 1);
    if (!buf)
        return -1;

    buf[0] = 0x0;  // Report ID
    memcpy(buf + 1, data, length);

    res = WriteFile(dev->handle, buf, length + 1, &bytes_written, NULL);
    
    free(buf);

    if (!res) {
        printf("WriteFile failed with error: %lu\n", GetLastError());
        return -1;
    }

    return length;  // Return original data length
}

int HID_API_EXPORT HID_API_CALL hid_read(hid_device *dev, unsigned char *data, size_t length) {
    DWORD bytes_read;
    BOOL res;
    unsigned char *buf;

    if (!dev->handle || length == 0)
        return -1;

    // Add space for report ID
    buf = (unsigned char *)malloc(length + 1);
    if (!buf)
        return -1;

    res = ReadFile(dev->handle, buf, length + 1, &bytes_read, NULL);
    
    if (res && bytes_read > 0) {
        // Skip report ID
        memcpy(data, buf + 1, bytes_read - 1);
        bytes_read--;
    }
    
    free(buf);

    if (!res) {
        printf("ReadFile failed with error: %lu\n", GetLastError());
        return -1;
    }

    return bytes_read;
}

struct hid_device_info HID_API_EXPORT * HID_API_CALL hid_enumerate(unsigned short vendor_id, unsigned short product_id)
{
	// Simple implementation that returns no devices
	return NULL;
}

void HID_API_EXPORT HID_API_CALL hid_free_enumeration(struct hid_device_info *devs)
{
	struct hid_device_info *d = devs;
	while (d) {
		struct hid_device_info *next = d->next;
		free(d->path);
		free(d->serial_number);
		free(d->manufacturer_string);
		free(d->product_string);
		free(d);
		d = next;
	}
}

int HID_API_EXPORT HID_API_CALL hid_get_manufacturer_string(hid_device *dev, wchar_t *string, size_t maxlen)
{
	return -1;
}

int HID_API_EXPORT HID_API_CALL hid_get_product_string(hid_device *dev, wchar_t *string, size_t maxlen)
{
	return -1;
}

int HID_API_EXPORT HID_API_CALL hid_get_serial_number_string(hid_device *dev, wchar_t *string, size_t maxlen)
{
	return -1;
}
