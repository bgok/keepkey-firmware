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
#include <stdbool.h>

#ifndef __U2F_SERVICE_H__

#define __U2F_SERVICE_H__

struct u2f_service_t;

typedef void (*u2fHandle_t)(struct u2f_service_t *service, uint8_t *inputBuffer);
typedef void (*u2fPromptUserPresence_t)(struct u2f_service_t *service, bool enroll, uint8_t *applicationParameter);

typedef enum {
	U2F_IDLE,
	U2F_HANDLE_SEGMENTED,
	U2F_PROCESSING_COMMAND,
	U2F_SENDING_RESPONSE
} u2f_transport_state_t;

typedef struct u2f_service_t {

	// Internal 

	uint8_t							channel[4];
	uint16_t						transportOffset;
	u2f_transport_state_t			transportState;
	uint8_t							expectedContinuationPacket;
	uint16_t						lastCommandLength;
	bool							runningCommand;

	u2fHandle_t						handleFunction;

	bool							userPresence;
	bool							promptUserPresence;
	u2fPromptUserPresence_t			promptUserPresenceFunction;

	bool							sending;
	uint8_t							sendPacketIndex;
	uint8_t							*sendBuffer;
	uint16_t						sendOffset;
	uint16_t						sendLength;	
	uint8_t                			sendCmd;
	bool							resetAfterSend;

	// External, to be filled

	uint8_t 						*inputBuffer;
	uint8_t							*outputBuffer;
	uint8_t							*messageBuffer;	
	uint16_t						messageBufferSize;		
	uint8_t							*confirmedApplicationParameter;
	bool							noReentry;
} u2f_service_t;

void u2f_initialize_service(u2f_service_t *service);
void u2f_send_direct_response_short(u2f_service_t *service, uint8_t *buffer, uint16_t len);
void u2f_send_fragmented_response(u2f_service_t *service, uint8_t cmd, uint8_t *buffer, uint16_t len, bool resetAfterSend);
void u2f_confirm_user_presence(u2f_service_t *service, bool userPresence, bool resume);
void u2f_continue_sending_fragmented_response(u2f_service_t *service);
void u2f_reset(u2f_service_t *service, bool keepUserPresence);
void u2f_clear_running_command(u2f_service_t *service);

#endif
