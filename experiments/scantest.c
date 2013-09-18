#include <stdlib.h>
#include <errno.h>
#include <curses.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define HCI_STATE_NONE       0
#define HCI_STATE_OPEN       2
#define HCI_STATE_SCANNING   3
#define HCI_STATE_FILTERING  4

struct hci_state {
  int device_id;
  int device_handle;
  struct hci_filter original_filter;
  int state;
  int has_error;
  char error_message[1024];
} hci_state;

#define EIR_FLAGS                   0X01
#define EIR_NAME_SHORT              0x08
#define EIR_NAME_COMPLETE           0x09
#define EIR_MANUFACTURE_SPECIFIC    0xFF

struct hci_state open_default_hci_device()
{
  struct hci_state current_hci_state = {0};

  current_hci_state.device_id = hci_get_route(NULL);

  if((current_hci_state.device_handle = hci_open_dev(current_hci_state.device_id)) < 0) 
  {
    current_hci_state.has_error = TRUE;
    snprintf(current_hci_state.error_message, sizeof(current_hci_state.error_message), "Could not open device: %s", strerror(errno));
    return current_hci_state;
  }

  // Set fd non-blocking
  int on = 1;
  if(ioctl(current_hci_state.device_handle, FIONBIO, (char *)&on) < 0)
  {
    current_hci_state.has_error = TRUE;
    snprintf(current_hci_state.error_message, sizeof(current_hci_state.error_message), "Could set device to non-blocking: %s", strerror(errno));
    return current_hci_state;
  }

  current_hci_state.state = HCI_STATE_OPEN;

  return current_hci_state;
}

void start_hci_scan(struct hci_state current_hci_state)
{
  if(hci_le_set_scan_parameters(current_hci_state.device_handle, 0x01, htobs(0x0010), htobs(0x0010), 0x00, 0x00, 1000) < 0) 
  {
    current_hci_state.has_error = TRUE;
    snprintf(current_hci_state.error_message, sizeof(current_hci_state.error_message), "Failed to set scan parameters: %s", strerror(errno));
    return;
  }

  if(hci_le_set_scan_enable(current_hci_state.device_handle, 0x01, 1, 1000) < 0) 
  {
    current_hci_state.has_error = TRUE;
    snprintf(current_hci_state.error_message, sizeof(current_hci_state.error_message), "Failed to enable scan: %s", strerror(errno));
    return;
  }

  current_hci_state.state = HCI_STATE_SCANNING;

  // Save the current HCI filter
  socklen_t olen = sizeof(current_hci_state.original_filter);
  if(getsockopt(current_hci_state.device_handle, SOL_HCI, HCI_FILTER, &current_hci_state.original_filter, &olen) < 0) 
  {
    current_hci_state.has_error = TRUE;
    snprintf(current_hci_state.error_message, sizeof(current_hci_state.error_message), "Could not get socket options: %s", strerror(errno));
    return;
  }

  // Create and set the new filter
  struct hci_filter new_filter;

  hci_filter_clear(&new_filter);
  hci_filter_set_ptype(HCI_EVENT_PKT, &new_filter);
  hci_filter_set_event(EVT_LE_META_EVENT, &new_filter);

  if(setsockopt(current_hci_state.device_handle, SOL_HCI, HCI_FILTER, &new_filter, sizeof(new_filter)) < 0) 
  {
    current_hci_state.has_error = TRUE;
    snprintf(current_hci_state.error_message, sizeof(current_hci_state.error_message), "Could not set socket options: %s", strerror(errno));
    return;
  }

  current_hci_state.state = HCI_STATE_FILTERING;
}

void stop_hci_scan(struct hci_state current_hci_state)
{
  if(current_hci_state.state == HCI_STATE_FILTERING)
  {
    current_hci_state.state = HCI_STATE_SCANNING;
    setsockopt(current_hci_state.device_handle, SOL_HCI, HCI_FILTER, &current_hci_state.original_filter, sizeof(current_hci_state.original_filter));
  }

  if(hci_le_set_scan_enable(current_hci_state.device_handle, 0x00, 1, 1000) < 0) 
  {
    current_hci_state.has_error = TRUE;
    snprintf(current_hci_state.error_message, sizeof(current_hci_state.error_message), "Disable scan failed: %s", strerror(errno));
  }

  current_hci_state.state = HCI_STATE_OPEN;
} 

void close_hci_device(struct hci_state current_hci_state)
{
  if(current_hci_state.state == HCI_STATE_OPEN)
  {
    hci_close_dev(current_hci_state.device_handle);
  }
}

void error_check_and_exit(struct hci_state current_hci_state)
{
  if(current_hci_state.has_error)
  {
    printw("ERROR: %s\n", current_hci_state.error_message);
    endwin();
    exit(1);
  }
}

void process_data(uint8_t *data, size_t data_len, le_advertising_info *info)
{
  printw("Test: %p and %d\n", data, data_len);
  if(data[0] == EIR_NAME_SHORT || data[0] == EIR_NAME_COMPLETE)
  {
    size_t name_len = data_len - 1;
    char *name = malloc(name_len + 1);
    memset(name, 0, name_len + 1);
    memcpy(name, &data[2], name_len);

    char addr[18];
    ba2str(&info->bdaddr, addr);

    printw("addr=%s name=%s\n", addr, name);

    free(name);
  }
  else if(data[0] == EIR_FLAGS)
  {
    printw("Flag type: len=%d\n", data_len);
    int i;
    for(i=1; i<data_len; i++)
    {
      printw("\tFlag data: 0x%0X\n", data[i]);
    }
  }
  else if(data[0] == EIR_MANUFACTURE_SPECIFIC)
  {
    printw("Manufacture specific type: len=%d\n", data_len);

    // TODO int company_id = data[current_index + 2] 

    int i;
    for(i=1; i<data_len; i++)
    {
      printw("\tData: 0x%0X\n", data[i]);
    }
  }
  else
  {
    printw("Unknown type: type=%X\n", data[0]);
  }
}

int get_rssi(bdaddr_t *bdaddr, struct hci_state current_hci_state)
{
  struct hci_dev_info di;
  if (hci_devinfo(current_hci_state.device_id, &di) < 0) {
    perror("Can't get device info");
    return(-1);
  }

  uint16_t handle;
// int hci_create_connection(int dd, const bdaddr_t *bdaddr, uint16_t ptype, uint16_t clkoffset, uint8_t rswitch, uint16_t *handle, int to);
// HCI_DM1 | HCI_DM3 | HCI_DM5 | HCI_DH1 | HCI_DH3 | HCI_DH5
  if (hci_create_connection(current_hci_state.device_handle, bdaddr, htobs(di.pkt_type & ACL_PTYPE_MASK), 0, 0x01, &handle, 25000) < 0) {
    perror("Can't create connection");
    // TODO close(dd);
    return(-1);
  }
  sleep(1);

  struct hci_conn_info_req *cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
  bacpy(&cr->bdaddr, bdaddr);
  cr->type = ACL_LINK;
  if(ioctl(current_hci_state.device_handle, HCIGETCONNINFO, (unsigned long) cr) < 0) {
    perror("Get connection info failed");
    return(-1);
  }

  int8_t rssi;
  if(hci_read_rssi(current_hci_state.device_handle, htobs(cr->conn_info->handle), &rssi, 1000) < 0) {
    perror("Read RSSI failed");
    return(-1);
  }

  printf("RSSI return value: %d\n", rssi);

  free(cr);

  usleep(10000);
  hci_disconnect(current_hci_state.device_handle, handle, HCI_OE_USER_ENDED_CONNECTION, 10000);
}

void main(void)
{
  initscr();
  timeout(0);

  struct hci_state current_hci_state = open_default_hci_device();

  error_check_and_exit(current_hci_state);

  start_hci_scan(current_hci_state);

  error_check_and_exit(current_hci_state);

  printw("Scanning...\n");

  int done = FALSE;
  int error = FALSE;
  while(!done && !error) 
  {
    int len = 0;
    unsigned char buf[HCI_MAX_EVENT_SIZE];
    while((len = read(current_hci_state.device_handle, buf, sizeof(buf))) < 0) 
    {
      if (errno == EINTR) 
      {
        done = TRUE;
        break;
      }

      if (errno == EAGAIN || errno == EINTR)
      {
        if(getch() == 'q') 
        {
          done = TRUE;
          break;
        }

        usleep(100);
        continue;
      }

      error = TRUE;
    }

    if(!done && !error)
    {
      evt_le_meta_event *meta = (void *)(buf + (1 + HCI_EVENT_HDR_SIZE));

      len -= (1 + HCI_EVENT_HDR_SIZE);

      if (meta->subevent != EVT_LE_ADVERTISING_REPORT)
      {
        continue;
      }

      le_advertising_info *info = (le_advertising_info *) (meta->data + 1);

      printw("Event: %d\n", info->evt_type);
      printw("Length: %d\n", info->length);

      if(info->length == 0)
      {
        continue;
      }

      int current_index = 0;
      int data_error = 0;

      while(!data_error && current_index < info->length)
      {
        size_t data_len = info->data[current_index];

        if(data_len + 1 > info->length)
        {
          printw("EIR data length is longer than EIR packet length. %d + 1 > %d", data_len, info->length);
          data_error = 1;
        }
        else
        {
          process_data(info->data + current_index + 1, data_len, info);
          //get_rssi(&info->bdaddr, current_hci_state);
          current_index += data_len + 1;
        }
      }
    }
  }

  if(error)
  {
    printw("Error scanning.");
  }

  stop_hci_scan(current_hci_state);

  error_check_and_exit(current_hci_state);

  close_hci_device(current_hci_state);

  endwin();
}
