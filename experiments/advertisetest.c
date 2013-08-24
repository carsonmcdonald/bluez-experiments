#include <stdlib.h>
#include <errno.h>
#include <curses.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define cmd_opcode_pack(ogf, ocf) (uint16_t)((ocf & 0x03ff)|(ogf << 10))

#define EIR_FLAGS                   0X01
#define EIR_NAME_SHORT              0x08
#define EIR_NAME_COMPLETE           0x09
#define EIR_MANUFACTURE_SPECIFIC    0xFF

void main(int argc, char **argv)
{
  if(argc != 2)
  {
    fprintf(stderr, "Usage: %s UUID\n", argv[0]);
    exit(1);
  }

  int device_id = hci_get_route(NULL);

  int device_handle = 0;
  if((device_handle = hci_open_dev(device_id)) < 0)
  {
    perror("Could not open device");
    exit(1);
  }

  le_set_advertising_parameters_cp adv_params_cp;
  memset(&adv_params_cp, 0, sizeof(adv_params_cp));
  adv_params_cp.min_interval = htobs(0x0800);
  adv_params_cp.max_interval = htobs(0x0800);
  //if (opt)
  //  adv_params_cp.advtype = atoi(opt);
  adv_params_cp.chan_map = 7;

  uint8_t status;
  struct hci_request rq;
  memset(&rq, 0, sizeof(rq));
  rq.ogf = OGF_LE_CTL;
  rq.ocf = OCF_LE_SET_ADVERTISING_PARAMETERS;
  rq.cparam = &adv_params_cp;
  rq.clen = LE_SET_ADVERTISING_PARAMETERS_CP_SIZE;
  rq.rparam = &status;
  rq.rlen = 1;

  int ret = hci_send_req(device_handle, &rq, 1000);
  if (ret < 0)
    goto done;

  le_set_advertising_data_cp adv_data_cp;
  memset(&adv_data_cp, 0, sizeof(adv_data_cp));

  adv_data_cp.length = htobs(30);

  adv_data_cp.data[0] = htobs(2);
  adv_data_cp.data[1] = htobs(EIR_FLAGS);
  adv_data_cp.data[2] = htobs(0x1A);

  adv_data_cp.data[3]  = htobs(26);
  adv_data_cp.data[4]  = htobs(EIR_MANUFACTURE_SPECIFIC);
  adv_data_cp.data[5]  = htobs(0x4C);
  adv_data_cp.data[6]  = htobs(0x00);
  adv_data_cp.data[7]  = htobs(0x02);
  adv_data_cp.data[8]  = htobs(0x15);
  adv_data_cp.data[9]  = htobs(0xE2);
  adv_data_cp.data[10] = htobs(0xC5);
  adv_data_cp.data[11] = htobs(0x6D);
  adv_data_cp.data[12] = htobs(0xB5);
  adv_data_cp.data[13] = htobs(0xDF);
  adv_data_cp.data[14] = htobs(0xFB);
  adv_data_cp.data[15] = htobs(0x48);
  adv_data_cp.data[16] = htobs(0xD2);
  adv_data_cp.data[17] = htobs(0xB0);
  adv_data_cp.data[18] = htobs(0x60);
  adv_data_cp.data[19] = htobs(0xD0);
  adv_data_cp.data[20] = htobs(0xF5);
  adv_data_cp.data[21] = htobs(0xA7);
  adv_data_cp.data[22] = htobs(0x10);
  adv_data_cp.data[23] = htobs(0x96);
  adv_data_cp.data[24] = htobs(0xE0);
  adv_data_cp.data[25] = htobs(0x00);
  adv_data_cp.data[26] = htobs(0x00);
  adv_data_cp.data[27] = htobs(0x00);
  adv_data_cp.data[28] = htobs(0x00);
  adv_data_cp.data[29] = htobs(0xFF);

  memset(&rq, 0, sizeof(rq));
  rq.ogf = OGF_LE_CTL;
  rq.ocf = OCF_LE_SET_ADVERTISING_DATA;
  rq.cparam = &adv_data_cp;
  rq.clen = LE_SET_ADVERTISING_DATA_CP_SIZE;
  rq.rparam = &status;
  rq.rlen = 1;

  ret = hci_send_req(device_handle, &rq, 1000);
  if (ret < 0)
    goto done;

  le_set_advertise_enable_cp advertise_cp;
  memset(&advertise_cp, 0, sizeof(advertise_cp));
  advertise_cp.enable = 0x01;

  memset(&rq, 0, sizeof(rq));
  rq.ogf = OGF_LE_CTL;
  rq.ocf = OCF_LE_SET_ADVERTISE_ENABLE;
  rq.cparam = &advertise_cp;
  rq.clen = LE_SET_ADVERTISE_ENABLE_CP_SIZE;
  rq.rparam = &status;
  rq.rlen = 1;

  ret = hci_send_req(device_handle, &rq, 1000);

done:
  hci_close_dev(device_handle);

  if (ret < 0) {
    fprintf(stderr, "Can't set advertise mode on hci%d: %s (%d)\n", device_id, strerror(errno), errno);
    exit(1);
  }

  if (status) {
    fprintf(stderr, "LE set advertise enable on hci%d returned status %d\n", device_id, status);
    exit(1);
  }
}
