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

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#ifndef __U2F_MSG_INIT_H__

#define __U2F_MSG_INIT_H__

void msg_init_app(void);
void u2f_set_transient_entry(uint8_t *appId, char *name);

#endif


