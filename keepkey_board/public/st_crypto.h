/** @defgroup AESError AES Error Codes 
  * @{
  */
#define AES_SUCCESS             (int32_t) (0)    /*!< AES of PRIVKEY Success */
#define AES_ERR_BAD_INPUT_SIZE  (int32_t) (3101) /*!<  AES of PRIVKEY Invalid input size */
#define AES_ERR_BAD_OPERATION   (int32_t) (3102) /*!<  AES of PRIVKEY Invalid operation */
#define AES_ERR_BAD_CONTEXT     (int32_t) (3103) /*!<  AES of PRIVKEY The AES context contains some invalid or uninitialized values */

#define AES_ERR_BAD_PARAMETER   (int32_t) (3104) /*!<  AES of PRIVKEY One of the expected function parameters is invalid */
#define INCLUDE_AES192  /*!< This defines if AES functions with key size of 192 bit are included in the library \n If it's \b NOT defined then aes192.c is not needed. */



#ifdef INCLUDE_AES256
# define CRL_AES_MAX_EXPKEY_SIZE 60 /*!< The max size of the AES expanded key (in uint32_t) according to the INCLUDE OPTIONS */
# else
#   ifdef INCLUDE_AES192
#     define CRL_AES_MAX_EXPKEY_SIZE 52 /*!< The max size of the AES expanded key (in uint32_t) according to the INCLUDE OPTIONS */
#   else
#     define CRL_AES_MAX_EXPKEY_SIZE 44 /*!< The max size of the AES expanded key (in uint32_t) according to the INCLUDE OPTIONS */
#   endif
#endif /*include aes 256 */


/** @addtogroup SymKey
  * @{
  */

typedef enum {  
  E_SK_DEFAULT = (uint32_t) (0x00000000), /*!< User Flag: No flag specified. This is the default value that should be set to this flag  */  
  E_SK_DONT_PERFORM_KEY_SCHEDULE = (uint32_t) (0x00000001), /*!< User Flag: Used to force the init to not reperform key schedule.\n
                                                                 The classic example is where the same key is used on a new message, in this case to redo key scheduling is
                                                                 a useless waste of computation, could be particularly useful on GCM, where key schedule is very complicated. */    
  E_SK_USE_DMA = (uint32_t) (0x00000008), /*!< User Flag: Used only when there is an HW engine for AES/DES, it specifies if the DMA should be used to transfer
                                                                  data or the CPU should be used instead. It is common to always use the DMA, except when DMA is very busy or
                                                                  input data is very small */
  E_SK_FINAL_APPEND = (uint32_t) (0x00000020),   /*!< User Flag: Must be set in CMAC mode before the final Append call occurs. */
  E_SK_OPERATION_COMPLETED  = (uint32_t) (0x00000002),   /*!< Internal Flag (not to be set/read by user): used to check that the Finish function has been already called */  
  E_SK_NO_MORE_APPEND_ALLOWED = (uint32_t) (0x00000004), /*!< Internal Flag (not to be set/read by user): it is set when the last append has been called. Used where the append is called with an InputSize not
                                                                    multiple of the block size, which means that is the last input.*/
  E_SK_NO_MORE_HEADER_APPEND_ALLOWED = (uint32_t) (0x00000010),   /*!< Internal Flag (not to be set/read by user): only for authenticated encryption modes. \n
                                                                      It is set when the last header append has been called. Used where the header append is called with an InputSize not
                                                                      multiple of the block size, which means that is the last input.*/
  E_SK_APPEND_DONE = (uint32_t) (0x00000040),   /*!< Internal Flag (not to be set/read by user): only for CMAC.It is set when the first append has been called */
} SKflags_et; /*!< Type definitation for Symmetric Key Flags */



/** @addtogroup AESCBC
  * @{
  */  
typedef struct
{  
  uint32_t   mContextId; /*!< Unique ID of this context. \b Not \b used in current implementation. */  
  SKflags_et mFlags; /*!< 32 bit mFlags, used to perform keyschedule, choose betwen hw/sw/hw+dma and future use */  
  const uint8_t *pmKey; /*!< Pointer to original Key buffer */  
  const uint8_t *pmIv; /*!< Pointer to original Initialization Vector buffer */  
  int32_t   mIvSize; /*!< Size of the Initialization Vector in bytes */  
  uint32_t   amIv[4]; /*!< Temporary result/IV */  
  int32_t   mKeySize; /*!< Key length in bytes */
  uint32_t   amExpKey[CRL_AES_MAX_EXPKEY_SIZE]; /*!< Expanded AES key */
} AESCBCctx_stt; /*!< AES context structure for CBC mode */

/********************************************/
int32_t AES_AAA_Encrypt_Init(AESCBCctx_stt *P_pAESAAActx, const uint8_t *P_pKey, const uint8_t *P_pIv);
