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

#define EIR_NAME_SHORT              0x08  /* shortened local name */
#define EIR_NAME_COMPLETE           0x09  /* complete local name */

static void eir_parse_name(uint8_t *eir, size_t eir_len, char **buf)
{
  size_t data_len = eir[0];

  if(data_len + 1 > eir_len)
  {
    fprintf(stderr, "EIR data length is longer than EIR packet length. %d + 1 > %d", data_len, eir_len);
    return;
  }

  if(eir[1] == EIR_NAME_SHORT || eir[1] == EIR_NAME_COMPLETE)
  {
    size_t name_len = data_len - 1;
    *buf = malloc(name_len + 1);
    memset(*buf, 0, name_len + 1);
    memcpy(*buf, &eir[2], name_len);

    printw("Test: %s and %d\n", *buf, name_len);
  }
  else
  {
    printw("EIR not name type: %x\n", eir[1]);
  }
}

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
    current_hci_state.state = TRUE;
    snprintf(current_hci_state.error_message, sizeof(current_hci_state.error_message), "Failed to set scan parameters: %s", strerror(errno));
    return;
  }

  if(hci_le_set_scan_enable(current_hci_state.device_handle, 0x01, 1, 1000) < 0) 
  {
    current_hci_state.state = TRUE;
    snprintf(current_hci_state.error_message, sizeof(current_hci_state.error_message), "Failed to enable scan: %s", strerror(errno));
    return;
  }

  current_hci_state.state = HCI_STATE_SCANNING;

  // Save the current HCI filter
  socklen_t olen = sizeof(current_hci_state.original_filter);
  if(getsockopt(current_hci_state.device_handle, SOL_HCI, HCI_FILTER, &current_hci_state.original_filter, &olen) < 0) 
  {
    current_hci_state.state = TRUE;
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
    current_hci_state.state = TRUE;
    snprintf(current_hci_state.error_message, sizeof(current_hci_state.error_message), "Could not set socket options: %s", strerror(errno));
    return;
  }

  current_hci_state.state = HCI_STATE_FILTERING;
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
        break;
      }

      le_advertising_info *info = (le_advertising_info *) (meta->data + 1);

      char *name = NULL;
      eir_parse_name(info->data, info->length, &name);

      if(name)
      {
        char addr[18];
        ba2str(&info->bdaddr, addr);

        printw("addr=%s name=%s\n", addr, name);

        free(name);
      }
    }
  }

  if(current_hci_state.state == HCI_STATE_FILTERING)
  {
    current_hci_state.state = HCI_STATE_SCANNING;
    setsockopt(current_hci_state.device_handle, SOL_HCI, HCI_FILTER, &current_hci_state.original_filter, sizeof(current_hci_state.original_filter));
  }

  if(error)
  {
    perror("Could not receive advertising events");
    endwin();
    exit(1);
  }

  if(hci_le_set_scan_enable(current_hci_state.device_handle, 0x00, 1, 1000) < 0) 
  {
    perror("Disable scan failed");
    endwin();
    exit(1);
  }
 
  hci_close_dev(current_hci_state.device_handle);

  endwin();
}
