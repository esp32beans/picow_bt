/*
 * Copyright (C) 2014 BlueKitchen GmbH
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holders nor the names of
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 * 4. Any redistribution, use, or modification is done solely for
 *    personal benefit and not for any commercial purpose or for
 *    monetary gain.
 *
 * THIS SOFTWARE IS PROVIDED BY BLUEKITCHEN GMBH AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL BLUEKITCHEN
 * GMBH OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Please inquire about commercial licensing options at
 * contact@bluekitchen-gmbh.com
 *
 */

#define printf(...) Serial.printf(__VA_ARGS__)

#define BTSTACK_FILE__ "gap_dual.ino"

// *****************************************************************************
/* EXAMPLE_START(gap_inquiry): GAP Classic Inquiry
 *
 * @text The Generic Access Profile (GAP) defines how Bluetooth devices discover
 * and establish a connection with each other. In this example, the application
 * discovers  surrounding Bluetooth devices and collects their Class of Device
 * (CoD), page scan mode, clock offset, and RSSI. After that, the remote name of
 * each device is requested. In the following section we outline the Bluetooth
 * logic part, i.e., how the packet handler handles the asynchronous events and
 * data packets.
 */
// *****************************************************************************

#include <sdkoverride/bluetooth.h>
#include <_needsbt.h>
#include <pico/cyw43_arch.h>
#include "btstack.h"

static void lockBluetooth() {
  async_context_acquire_lock_blocking(cyw43_arch_async_context());
}

static void unlockBluetooth() {
  async_context_release_lock(cyw43_arch_async_context());
}

#define MAX_DEVICES 20
enum DEVICE_STATE {
  REMOTE_NAME_REQUEST,
  REMOTE_NAME_INQUIRED,
  REMOTE_NAME_FETCHED
};
struct device {
  bd_addr_t address;
  uint8_t pageScanRepetitionMode;
  uint16_t clockOffset;
  enum DEVICE_STATE state;
};

#define INQUIRY_INTERVAL 5
// ## BLE

/* @section GAP LE Advertising Data Dumper
 *
 * @text Here, we use the definition of advertising data types and flags as
 * specified in [Assigned Numbers
 * GAP](https://www.bluetooth.org/en-us/specification/assigned-numbers/generic-access-profile)
 * and [Supplement to the Bluetooth Core Specification,
 * v4](https://www.bluetooth.org/DocMan/handlers/DownloadDoc.ashx?doc_id=282152).
 */

static const char *ad_types[] = {
    "",
    "Flags",
    "Incomplete List of 16-bit Service Class UUIDs",
    "Complete List of 16-bit Service Class UUIDs",
    "Incomplete List of 32-bit Service Class UUIDs",
    "Complete List of 32-bit Service Class UUIDs",
    "Incomplete List of 128-bit Service Class UUIDs",
    "Complete List of 128-bit Service Class UUIDs",
    "Shortened Local Name",
    "Complete Local Name",
    "Tx Power Level",
    "",
    "",
    "Class of Device",
    "Simple Pairing Hash C",
    "Simple Pairing Randomizer R",
    "Device ID",
    "Security Manager TK Value",
    "Slave Connection Interval Range",
    "",
    "List of 16-bit Service Solicitation UUIDs",
    "List of 128-bit Service Solicitation UUIDs",
    "Service Data",
    "Public Target Address",
    "Random Target Address",
    "Appearance",
    "Advertising Interval"};

static const char *flags[] = {
    "LE Limited Discoverable Mode",
    "LE General Discoverable Mode",
    "BR/EDR Not Supported",
    "Simultaneous LE and BR/EDR to Same Device Capable (Controller)",
    "Simultaneous LE and BR/EDR to Same Device Capable (Host)",
    "Reserved",
    "Reserved",
    "Reserved"};

/* @text BTstack offers an iterator for parsing sequence of advertising data
 * (AD) structures, see [BLE advertisements parser
 * API](../appendix/apis/#ble-advertisements-parser-api). After initializing the
 * iterator, each AD structure is dumped according to its type.
 */

static void dump_advertisement_data(const uint8_t *adv_data, uint8_t adv_size) {
  ad_context_t context;
  bd_addr_t address;
  uint8_t uuid_128[16];
  for (ad_iterator_init(&context, adv_size, (uint8_t *)adv_data);
       ad_iterator_has_more(&context); ad_iterator_next(&context)) {
    uint8_t data_type = ad_iterator_get_data_type(&context);
    uint8_t size = ad_iterator_get_data_len(&context);
    const uint8_t *data = ad_iterator_get_data(&context);

    if (data_type > 0 && data_type < 0x1B) {
      printf("    %s: ", ad_types[data_type]);
    }
    int i;
    // Assigned Numbers GAP

    switch (data_type) {
    case BLUETOOTH_DATA_TYPE_FLAGS:
      // show only first octet, ignore rest
      for (i = 0; i < 8; i++) {
        if (data[0] & (1 << i)) {
          printf("%s; ", flags[i]);
        }
      }
      break;
    case BLUETOOTH_DATA_TYPE_INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS:
    case BLUETOOTH_DATA_TYPE_COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS:
    case BLUETOOTH_DATA_TYPE_LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS:
      for (i = 0; i < size; i += 2) {
        printf("%02X ", little_endian_read_16(data, i));
      }
      break;
    case BLUETOOTH_DATA_TYPE_INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS:
    case BLUETOOTH_DATA_TYPE_COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS:
    case BLUETOOTH_DATA_TYPE_LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS:
      for (i = 0; i < size; i += 4) {
        printf("%04" PRIX32, little_endian_read_32(data, i));
      }
      break;
    case BLUETOOTH_DATA_TYPE_INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS:
    case BLUETOOTH_DATA_TYPE_COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS:
    case BLUETOOTH_DATA_TYPE_LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS:
      reverse_128(data, uuid_128);
      printf("%s", uuid128_to_str(uuid_128));
      break;
    case BLUETOOTH_DATA_TYPE_SHORTENED_LOCAL_NAME:
    case BLUETOOTH_DATA_TYPE_COMPLETE_LOCAL_NAME:
      for (i = 0; i < size; i++) {
        printf("%c", (char)(data[i]));
      }
      break;
    case BLUETOOTH_DATA_TYPE_TX_POWER_LEVEL:
      printf("%d dBm", *(int8_t *)data);
      break;
    case BLUETOOTH_DATA_TYPE_SLAVE_CONNECTION_INTERVAL_RANGE:
      printf("Connection Interval Min = %u ms, Max = %u ms",
             little_endian_read_16(data, 0) * 5 / 4,
             little_endian_read_16(data, 2) * 5 / 4);
      break;
    case BLUETOOTH_DATA_TYPE_SERVICE_DATA:
      printf_hexdump(data, size);
      break;
    case BLUETOOTH_DATA_TYPE_PUBLIC_TARGET_ADDRESS:
    case BLUETOOTH_DATA_TYPE_RANDOM_TARGET_ADDRESS:
      reverse_bd_addr(data, address);
      printf("%s", bd_addr_to_str(address));
      break;
    case BLUETOOTH_DATA_TYPE_APPEARANCE:
      // https://developer.bluetooth.org/gatt/characteristics/Pages/CharacteristicViewer.aspx?u=org.bluetooth.characteristic.gap.appearance.xml
      printf("%02X", little_endian_read_16(data, 0));
      break;
    case BLUETOOTH_DATA_TYPE_ADVERTISING_INTERVAL:
      printf("%u ms", little_endian_read_16(data, 0) * 5 / 8);
      break;
    case BLUETOOTH_DATA_TYPE_3D_INFORMATION_DATA:
      printf_hexdump(data, size);
      break;
    case BLUETOOTH_DATA_TYPE_MANUFACTURER_SPECIFIC_DATA: // Manufacturer
                                                         // Specific Data
      break;
    case BLUETOOTH_DATA_TYPE_CLASS_OF_DEVICE:
    case BLUETOOTH_DATA_TYPE_SIMPLE_PAIRING_HASH_C:
    case BLUETOOTH_DATA_TYPE_SIMPLE_PAIRING_RANDOMIZER_R:
    case BLUETOOTH_DATA_TYPE_DEVICE_ID:
    case BLUETOOTH_DATA_TYPE_SECURITY_MANAGER_OUT_OF_BAND_FLAGS:
    default:
      printf("Advertising Data Type 0x%2x not handled yet", data_type);
      break;
    }
    printf("\n");
  }
  printf("\n");
}

// ## Classic
struct device devices[MAX_DEVICES];
int deviceCount = 0;

enum STATE { INIT, ACTIVE };
enum STATE state = INIT;

static btstack_packet_callback_registration_t hci_event_callback_registration;

static int getDeviceIndexForAddress(bd_addr_t addr) {
  int j;
  for (j = 0; j < deviceCount; j++) {
    if (bd_addr_cmp(addr, devices[j].address) == 0) {
      return j;
    }
  }
  return -1;
}

static void start_scan(void) {
  printf("Starting scan..\n");
  lockBluetooth();
  gap_inquiry_start(INQUIRY_INTERVAL);
  unlockBluetooth();
}

static int has_more_remote_name_requests(void) {
  int i;
  for (i = 0; i < deviceCount; i++) {
    if (devices[i].state == REMOTE_NAME_REQUEST)
      return 1;
  }
  return 0;
}

static void do_next_remote_name_request(void) {
  int i;
  for (i = 0; i < deviceCount; i++) {
    // remote name request
    if (devices[i].state == REMOTE_NAME_REQUEST) {
      devices[i].state = REMOTE_NAME_INQUIRED;
      printf("Get remote name of %s...\n", bd_addr_to_str(devices[i].address));
      lockBluetooth();
      gap_remote_name_request(devices[i].address,
                              devices[i].pageScanRepetitionMode,
                              devices[i].clockOffset | 0x8000);
      unlockBluetooth();
      return;
    }
  }
}

static void continue_remote_names(void) {
  if (has_more_remote_name_requests()) {
    do_next_remote_name_request();
    return;
  }
  start_scan();
}

/* @section Bluetooth Logic
 *
 * @text The Bluetooth logic is implemented as a state machine within the packet
 * handler. In this example, the following states are passed sequentially:
 * INIT, and ACTIVE.
 */

static void packet_handler(uint8_t packet_type, uint16_t channel,
                           uint8_t *packet, uint16_t size) {
  UNUSED(channel);
  UNUSED(size);

  bd_addr_t addr;
  int i;
  int index;
  bd_addr_t address;
  uint8_t address_type;
  uint8_t event_type;
  int8_t rssi;
  uint8_t length;
  const uint8_t *data;

  if (packet_type != HCI_EVENT_PACKET)
    return;

  uint8_t event = hci_event_packet_get_type(packet);

  switch (state) {
  /* @text In INIT, an inquiry  scan is started, and the application transits to
   * ACTIVE state.
   */
  case INIT:
    switch (event) {
    case BTSTACK_EVENT_STATE:
      if (btstack_event_state_get_state(packet) == HCI_STATE_WORKING) {
        start_scan();
        lockBluetooth();
        gap_start_scan();
        unlockBluetooth();
        state = ACTIVE;
      }
      break;
    default:
      break;
    }
    break;

  /* @text In ACTIVE, the following events are processed:
   *  - GAP Inquiry result event: BTstack provides a unified inquiry result that
   * contain Class of Device (CoD), page scan mode, clock offset. RSSI and name
   * (from EIR) are optional.
   *  - Inquiry complete event: the remote name is requested for devices without
   * a fetched name. The state of a remote name can be one of the following:
   *    REMOTE_NAME_REQUEST, REMOTE_NAME_INQUIRED, or REMOTE_NAME_FETCHED.
   *  - Remote name request complete event: the remote name is stored in the
   * table and the state is updated to REMOTE_NAME_FETCHED. The query of remote
   * names is continued.
   */
  case ACTIVE:
    switch (event) {

    case GAP_EVENT_INQUIRY_RESULT:
      if (deviceCount >= MAX_DEVICES)
        break; // already full
      gap_event_inquiry_result_get_bd_addr(packet, addr);
      index = getDeviceIndexForAddress(addr);
      if (index >= 0)
        break; // already in our list

      memcpy(devices[deviceCount].address, addr, 6);
      devices[deviceCount].pageScanRepetitionMode =
          gap_event_inquiry_result_get_page_scan_repetition_mode(packet);
      devices[deviceCount].clockOffset =
          gap_event_inquiry_result_get_clock_offset(packet);
      // print info
      printf("Device found: %s ", bd_addr_to_str(addr));
      printf(
          "with COD: 0x%06x, ",
          (unsigned int)gap_event_inquiry_result_get_class_of_device(packet));
      printf("pageScan %d, ", devices[deviceCount].pageScanRepetitionMode);
      printf("clock offset 0x%04x", devices[deviceCount].clockOffset);
      if (gap_event_inquiry_result_get_rssi_available(packet)) {
        printf(", rssi %d dBm",
               (int8_t)gap_event_inquiry_result_get_rssi(packet));
      }
      if (gap_event_inquiry_result_get_name_available(packet)) {
        char name_buffer[240];
        int name_len = gap_event_inquiry_result_get_name_len(packet);
        memcpy(name_buffer, gap_event_inquiry_result_get_name(packet),
               name_len);
        name_buffer[name_len] = 0;
        printf(", name '%s'", name_buffer);
        devices[deviceCount].state = REMOTE_NAME_FETCHED;
        ;
      } else {
        devices[deviceCount].state = REMOTE_NAME_REQUEST;
      }
      printf("\n");
      deviceCount++;
      break;

    case GAP_EVENT_INQUIRY_COMPLETE:
      for (i = 0; i < deviceCount; i++) {
        // retry remote name request
        if (devices[i].state == REMOTE_NAME_INQUIRED)
          devices[i].state = REMOTE_NAME_REQUEST;
      }
      continue_remote_names();
      break;

    case HCI_EVENT_REMOTE_NAME_REQUEST_COMPLETE:
      reverse_bd_addr(&packet[3], addr);
      index = getDeviceIndexForAddress(addr);
      if (index >= 0) {
        if (packet[2] == 0) {
          printf("Name: '%s'\n", &packet[9]);
          devices[index].state = REMOTE_NAME_FETCHED;
        } else {
          printf("Failed to get name: page timeout\n");
        }
      }
      continue_remote_names();
      break;

  case GAP_EVENT_ADVERTISING_REPORT:
    gap_event_advertising_report_get_address(packet, address);
    event_type =
        gap_event_advertising_report_get_advertising_event_type(packet);
    address_type = gap_event_advertising_report_get_address_type(packet);
    rssi = gap_event_advertising_report_get_rssi(packet);
    length = gap_event_advertising_report_get_data_length(packet);
    data = gap_event_advertising_report_get_data(packet);
    if (rssi > -70) {
      printf("Advertisement (legacy) event: evt-type %u, addr-type %u,"
             " addr %s, rssi %d, data[%u] ",
             event_type, address_type, bd_addr_to_str(address), rssi, length);
      printf_hexdump(data, length);
      dump_advertisement_data(data, length);
    }
    break;

#ifdef ENABLE_LE_EXTENDED_ADVERTISING
  case GAP_EVENT_EXTENDED_ADVERTISING_REPORT:
    gap_event_extended_advertising_report_get_address(packet, address);
    event_type =
        gap_event_extended_advertising_report_get_advertising_event_type(
            packet);
    address_type =
        gap_event_extended_advertising_report_get_address_type(packet);
    rssi = gap_event_extended_advertising_report_get_rssi(packet);
    length = gap_event_extended_advertising_report_get_data_length(packet);
    data = gap_event_extended_advertising_report_get_data(packet);
    printf("Advertisement (extended) event: evt-type %u, addr-type %u"
           ", addr %s, rssi %d, data[%u] ",
           event_type, address_type, bd_addr_to_str(address), rssi, length);
    printf_hexdump(data, length);
    dump_advertisement_data(data, length);
    break;
#endif

    default:
      break;
    }
    break;

  default:
    break;
  }
}

/* @text For more details on discovering remote devices, please see
 * Section on [GAP](../profiles/#sec:GAPdiscoverRemoteDevices).
 */

/* @section Main Application Setup
 *
 * @text Listing MainConfiguration shows main application code.
 * It registers the HCI packet handler and starts the Bluetooth stack.
 */

/* LISTING_START(MainConfiguration): Setup packet handler for GAP inquiry */
int btstack_main(void);
int btstack_main(void) {
  // BLE: Active scanning, 100% (scan interval = scan window)
  lockBluetooth();
  gap_set_scan_parameters(1, 48, 48);

  // Classic: enabled EIR
  hci_set_inquiry_mode(INQUIRY_MODE_RSSI_AND_EIR);

  hci_event_callback_registration.callback = &packet_handler;
  hci_add_event_handler(&hci_event_callback_registration);

  // turn on!
  hci_power_control(HCI_POWER_ON);
  unlockBluetooth();

  return 0;
}
/* LISTING_END */
/* EXAMPLE_END */

void setup(void) {
  Serial.begin(115200);
  while (!Serial && (millis() < 3000)) delay(1);
  Serial.println(BTSTACK_FILE__);
  btstack_main();
}

void loop(void) {}
