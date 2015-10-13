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
#include "u2f_service.h"
#include "u2f_transport.h"

#define U2F_MASK_COMMAND 0x80
#define U2F_COMMAND_HEADER_SIZE 3

static const uint8_t BROADCAST_CHANNEL[] = { 0xff, 0xff, 0xff, 0xff };

void u2f_transport_handle(u2f_service_t *service, uint8_t *buffer, uint16_t size) {
	// If busy, answer immediately - this could be delegated to the upper layer
	if ((service->transportState == U2F_PROCESSING_COMMAND) || (service->transportState == U2F_SENDING_RESPONSE)) {
			u2f_response_error(service, ERROR_CHANNEL_BUSY, false);
			goto error;					
	}
	if (size < 5) {
		// Message to short, abort
		u2f_response_error(service, ERROR_PROP_MESSAGE_TOO_SHORT, true);
		goto error;			
	}
	if ((buffer[4]  & U2F_MASK_COMMAND) != 0) {
		if (size < 8) {
			// Message to short, abort
			u2f_response_error(service, ERROR_PROP_MESSAGE_TOO_SHORT, true);
			goto error;			
		}
		// Check the channel - broadcast channel is only allowed for INIT
		if (memcmp(buffer, service->channel, 4) != 0) {
			if (!((memcmp(buffer, BROADCAST_CHANNEL, 4) == 0) && (buffer[4] == U2F_CMD_INIT))) {
				u2f_response_error(service, ERROR_CHANNEL_BUSY, true);
				goto error;
			}
		}
		// Check the length
		uint16_t commandLength = (buffer[5] << 8) | (buffer[6]);
		if (commandLength > (service->messageBufferSize - 3)) {
			// Overflow in message size, abort
			u2f_response_error(service, ERROR_PROP_COMMAND_TOO_LONG, true);
			goto error;
		}
		// Check if the command is supported
		switch(buffer[4]) {
			case U2F_CMD_PING:
			case U2F_CMD_MSG:
			case U2F_CMD_INIT:
				break;
			default:
				// Unknown command, abort
				u2f_response_error(service, ERROR_PROP_UNKNOWN_COMMAND, true);
				goto error;
		}
		// Ok, initialize the buffer
		service->lastCommandLength = commandLength;
		service->expectedContinuationPacket = 0;
		memcpy(service->messageBuffer, buffer + 4, size - 4);
		service->transportOffset = size - 4;
	}
	else {
		// Continuation
		if (size < 6) {
			// Message to short, abort
			u2f_response_error(service, ERROR_PROP_MESSAGE_TOO_SHORT, true);
			goto error;			
		}
		if (service->transportState != U2F_HANDLE_SEGMENTED) {
			// Unexpected continuation at this stage, abort
			u2f_response_error(service, ERROR_PROP_UNEXPECTED_CONTINUATION, true);
			goto error;
		}
		if (buffer[4] != service->expectedContinuationPacket) {
			// Bad continuation packet, abort
			u2f_response_error(service, ERROR_PROP_INVALID_CONTINUATION, true);
			goto error;
		}
		if ((service->transportOffset + (size - 5)) > (service->messageBufferSize - 3)) {
			// Overflow, abort
			u2f_response_error(service, ERROR_PROP_CONTINUATION_OVERFLOW, true);
			goto error;			
		}
		memcpy(service->messageBuffer + service->transportOffset, buffer + 5, size - 5);
		service->transportOffset += size - 5;
		service->expectedContinuationPacket++;
	}
	// See if we can process the command
	if (service->transportOffset >= (service->lastCommandLength + U2F_COMMAND_HEADER_SIZE)) {		
		service->transportState = U2F_PROCESSING_COMMAND;
		service->handleFunction(service, service->messageBuffer);
	}
	else {
		service->transportState = U2F_HANDLE_SEGMENTED;
	}
	return;
error:
	return;	
}

void u2f_response_error(u2f_service_t *service, char errorCode, bool reset) {
	memset(service->outputBuffer, 0, 64);
	memcpy(service->outputBuffer, service->channel, 4);
	service->outputBuffer[4] = U2F_STATUS_ERROR;
	service->outputBuffer[5] = 0x00;
	service->outputBuffer[6] = 0x01;
	service->outputBuffer[7] = errorCode;
	u2f_send_direct_response_short(service, service->outputBuffer, 8);
	if (reset) {
		u2f_reset(service, true);
	}
}
