/*
*******************************************************************************    
*   Portable FIDO U2F implementation
*   KeepKey specific initialization
*   (c) 2015 Ledger
*   
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*   limitations under the License.
********************************************************************************/

#include "msg_init_app.h"

#if HAVE_U2F

#include "layout.h"
#include "keepkey_display.h"
#include "msg_dispatch.h"
#include "resources.h"
#include "confirm_sm.h"
#include "usb_driver.h"
#include "home_sm.h"
#include "util.h"

#include "u2f_service.h"
#include "u2f_transport.h"
#include "u2f_crypto.h"

#define FIDO_INS_ENROLL 0x01
#define FIDO_INS_SIGN 0x02

#define U2F_MAX_MESSAGE_SIZE 1024

u2f_service_t u2fService;
static uint8_t  u2fInputBuffer[USB_SEGMENT_SIZE];
static uint8_t  u2fOutputBuffer[USB_SEGMENT_SIZE];
static uint8_t  u2fMessageBuffer[U2F_MAX_MESSAGE_SIZE];
static uint8_t  u2fConfirmedApplicationParameter[32];
static const Image    *wellKnownImage = NULL;
static U2fWellKnown u2fWellKnownTransient = { 0 };

void u2f_set_transient_entry(uint8_t *appId, char *name) {
  memcpy(u2fWellKnownTransient.appId, appId, 32);
  strcpy(u2fWellKnownTransient.commonName, name);
}

void u2f_notification(const char *str1, const char *str2, NotificationType type) {
  DrawableParams sp;
  layout_standard_notification(str1, str2, type);
  if (wellKnownImage != NULL) {
    sp.x = KEEPKEY_DISPLAY_WIDTH - 32 - 2;
    sp.y = KEEPKEY_DISPLAY_HEIGHT - 32 - 2;
    draw_bitmap_mono_rle(layout_get_canvas(), &sp, wellKnownImage);
  }
}

void prompt_user_presence(u2f_service_t *service, bool enroll, uint8_t *applicationParameter) {
  (void)applicationParameter;
  char message[200];
  const U2fWellKnown *wellKnown = get_u2f_well_known();
  int i = 0;
  while (wellKnown[i].image != NULL) {
    if (memcmp(applicationParameter, wellKnown[i].appId, 32) == 0) {
      break;
    }
    i++;
  }
  strcpy(message, (enroll ? "Confirm new account creation" : "Confirm login"));
  strcat(message, "\n");
  if (wellKnown[i].image != NULL) {
    strcat(message, wellKnown[i].commonName);
    wellKnownImage = wellKnown[i].image;
  }
  else
  if (memcmp(applicationParameter, u2fWellKnownTransient.appId, 32) == 0) {
    strcat(message, u2fWellKnownTransient.commonName);
    wellKnownImage = get_ledger_logo_image();
  }
  else {
    wellKnownImage = get_ledger_logo_image();
    strcat(message, "App ID ");
    data2hex(applicationParameter, 4, message + strlen(message));
    strcat(message, " ... ");
    data2hex(applicationParameter + 32 - 4, 4, message + strlen(message));
  }
  bool confirmed = confirm_with_custom_layout_without_button_request((layout_notification_t)&u2f_notification, 
      "U2F authentication", 
      message);
  u2f_confirm_user_presence(service, confirmed, false);
  u2f_reset(service, true);
  go_home();
}

static void handle_u2f_usb_rx(UsbMessage *msg)
{
  u2f_transport_handle(&u2fService, msg->message, USB_SEGMENT_SIZE);
}

#endif

void msg_init_app() {
#if HAVE_U2F
  memset((uint8_t*)&u2fService, 0, sizeof(u2fService));
  u2fService.promptUserPresenceFunction = (u2fPromptUserPresence_t)prompt_user_presence;
  u2fService.inputBuffer = u2fInputBuffer;
  u2fService.outputBuffer = u2fOutputBuffer;
  u2fService.messageBuffer = u2fMessageBuffer;
  u2fService.messageBufferSize = U2F_MAX_MESSAGE_SIZE;
  u2fService.confirmedApplicationParameter = u2fConfirmedApplicationParameter;
  u2f_initialize_service(&u2fService);	
  u2f_crypto_init();     
  usb_set_u2f_rx_callback(handle_u2f_usb_rx);
#endif
}

