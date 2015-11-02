/*
*******************************************************************************    
*   Portable FIDO U2F implementation
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

#include <stdint.h>
#include <string.h>
#include "usb_driver.h"
#include "u2f_service.h"
#include "u2f_transport.h"
#include "u2f_processing.h"

#if HAVE_U2F

void u2f_reset(u2f_service_t *service, bool keepUserPresence) {
	service->transportState = U2F_IDLE;	
	service->promptUserPresence = false;
	if (!keepUserPresence) {
		service->userPresence = false;
		memset(service->confirmedApplicationParameter, 0, 32);
	}
}

void u2f_clear_running_command(u2f_service_t *service) {
	service->runningCommand = false;
}

void u2f_initialize_service(u2f_service_t *service) {
    service->handleFunction = (u2fHandle_t)u2f_process_message;
    u2f_reset(service, false);
}

void u2f_send_direct_response_short(u2f_service_t *service, uint8_t *buffer, uint16_t len) {
	(void)service;
	if (len > USB_SEGMENT_SIZE) {
		return;
	}
	usb_u2f_tx(buffer, len);
}

void u2f_send_fragmented_response(u2f_service_t *service, uint8_t cmd, uint8_t *buffer, uint16_t len, bool resetAfterSend) {
	if (resetAfterSend) {
		service->transportState = U2F_SENDING_RESPONSE;
	}
	service->sending = true;
	service->sendPacketIndex = 0;
	service->sendBuffer = buffer;
	service->sendOffset = 0;
	service->sendLength = len;
	service->sendCmd = cmd;
	service->resetAfterSend = resetAfterSend;
	u2f_continue_sending_fragmented_response(service);
}

void u2f_continue_sending_fragmented_response(u2f_service_t *service) {
	do {
		uint8_t headerSize = (service->sendPacketIndex == 0 ? 7 : 5);
		uint16_t blockSize = ((service->sendLength - service->sendOffset) > (USB_SEGMENT_SIZE - headerSize) ? (USB_SEGMENT_SIZE - headerSize) : service->sendLength - service->sendOffset);
		uint16_t dataSize = blockSize + headerSize;
		// Fragment
		memset(service->outputBuffer, 0, USB_SEGMENT_SIZE);
		memcpy(service->outputBuffer, service->channel, 4);
		if (service->sendPacketIndex == 0) {
			service->outputBuffer[4] = service->sendCmd;
			service->outputBuffer[5] = (service->sendLength >> 8);
			service->outputBuffer[6] = (service->sendLength & 0xff);			
		}
		else {
			service->outputBuffer[4] = (service->sendPacketIndex - 1);
		}
		if (service->sendBuffer != NULL) {
			memcpy(service->outputBuffer + headerSize, service->sendBuffer + service->sendOffset, blockSize);
		}
		usb_u2f_tx(service->outputBuffer, dataSize);
		service->sendOffset += blockSize;
		service->sendPacketIndex++;
	}
	while(service->sendOffset != service->sendLength);
	if (service->sendOffset == service->sendLength) {
		service->sending = false;
		if (service->resetAfterSend) {
			u2f_reset(service, false);
		}
	}
}

void u2f_confirm_user_presence(u2f_service_t *service, bool userPresence, bool resume) {
	service->userPresence = userPresence;
	if (userPresence && service->promptUserPresence && resume) {
		// resume command interpretation 
		service->handleFunction(service, service->messageBuffer);
	}
	service->promptUserPresence = false;
}

#endif

