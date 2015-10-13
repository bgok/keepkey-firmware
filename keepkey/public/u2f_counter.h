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

#ifndef __U2F_COUNTER_H__

#define __U2F_COUNTER_H__

void u2f_counter_init(void);
uint8_t u2f_counter_increase_and_get(uint8_t *buffer);

#endif