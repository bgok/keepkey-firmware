#include <stdint.h>
#include <st_crypto.h>
#include "keepkey_board.h"
#include <keepkey_usart.h>

extern int32_t AES_CBC_Encrypt_Init(AESCBCctx_stt *, uint8_t *, uint8_t *);
extern int32_t AES_CBC_Encrypt_Append(AESCBCctx_stt *, uint8_t *, uint32_t, uint8_t *, int32_t *);
extern int32_t AES_CBC_Encrypt_Finish(AESCBCctx_stt *, uint8_t *, int32_t *);
extern void Crypto_DeInit(void);


/* Private typedef -----------------------------------------------------------*/
typedef enum {FAILED = 0, PASSED = !FAILED} TestStatus;
/* Private define ------------------------------------------------------------*/
#define PLAINTEXT_LENGTH 64
#define CRL_AES192_KEY   24 /*!< Number of bytes (uint8_t) necessary to store an AES key of 192 bits. */
#define CRL_AES192_EXPANDED_KEY  52 /*!< Number of ints (uint32_t) necessary to store an expanded AES key of 192 bits. */
#define CRL_AES256_KEY   32 /*!< Number of bytes (uint8_t) necessary to store an AES key of 256 bits. */
#define CRL_AES256_EXPANDED_KEY  60 /*!< Number of ints (uint32_t) necessary to store an expanded AES key of 256 bits. */
#define CRL_AES_BLOCK     16 /*!< Number of bytes (uint8_t) necessary to store an AES block. */
/* Private macro -------------------------------------------------------------*/
typedef enum {DISABLE = 0, ENABLE = !DISABLE} FunctionalState;
/* Private variables ---------------------------------------------------------*/
const uint8_t Plaintext[PLAINTEXT_LENGTH] =
  {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
  };

/* Key to be used for AES encryption/decryption */
uint8_t Key[CRL_AES192_KEY] =
  {
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
    0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
  };

/* Initialization Vector */
uint8_t IV[CRL_AES_BLOCK] =
  {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  };


/* Buffer to store the output data */
uint8_t OutputMessage[PLAINTEXT_LENGTH];

/* Size of the output data */
uint32_t OutputMessageLength = 0;

const uint8_t Expected_Ciphertext[PLAINTEXT_LENGTH] =
  {
    0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d,
    0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8,
    0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4,
    0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a,
    0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0,
    0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0,
    0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81,
    0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd,
  };

/***************************************************************************************/
/***************************************************************************************/
/***************************************************************************************/
/***************************************************************************************/
/***************************************************************************************/
/***************************************************************************************/
/***************************************************************************************/
void RCC_AHB1PeriphClockCmd(uint32_t RCC_AHB1Periph, FunctionalState NewState)
{
    (void)NewState;
    (void)RCC_AHB1Periph;
    dbg_print("pkhoo:%s\n\r", __FUNCTION__);
}
/**
  * @brief  AES CBC Encryption example.
  * @param  InputMessage: pointer to input message to be encrypted.
  * @param  InputMessageLength: input data message length in byte.
  * @param  AES192_Key: pointer to the AES key to be used in the operation
  * @param  InitializationVector: pointer to the Initialization Vector (IV)
  * @param  IvLength: IV length in bytes.
  * @param  OutputMessage: pointer to output parameter that will handle the encrypted message
  * @param  OutputMessageLength: pointer to encrypted message length.
  * @retval error status: can be AES_SUCCESS if success or one of
  *         AES_ERR_BAD_INPUT_SIZE, AES_ERR_BAD_OPERATION, AES_ERR_BAD_CONTEXT
  *         AES_ERR_BAD_PARAMETER if error occured.
  */
int32_t STM32_AES_CBC_Encrypt(uint8_t* InputMessage,
                        uint32_t InputMessageLength,
                        uint8_t  *AES192_Key,
                        uint8_t  *InitializationVector,
                        uint32_t  IvLength,
                        uint8_t  *OutputMessage,
                        uint32_t *OutputMessageLength)
{
  AESCBCctx_stt AESctx;

  uint32_t error_status = AES_SUCCESS;

  int32_t outputLength = 0;

  /* Set flag field to default value */
  AESctx.mFlags = E_SK_DEFAULT;

  /* Set key size to 24 (corresponding to AES-192) */
  AESctx.mKeySize = 24;

  /* Set iv size field to IvLength*/
  AESctx.mIvSize = IvLength;

  /* Initialize the operation, by passing the key.
   * Third parameter is NULL because CBC doesn't use any IV */
  error_status = AES_CBC_Encrypt_Init(&AESctx, AES192_Key, InitializationVector );

  /* check for initialization errors */
  if (error_status == AES_SUCCESS)
  {
    /* Encrypt Data */
    error_status = AES_CBC_Encrypt_Append(&AESctx,
                                          InputMessage,
                                          InputMessageLength,
                                          OutputMessage,
                                          &outputLength);

    if (error_status == AES_SUCCESS)
    {
      /* Write the number of data written*/
      *OutputMessageLength = outputLength;
      /* Do the Finalization */
      error_status = AES_CBC_Encrypt_Finish(&AESctx, OutputMessage + *OutputMessageLength, &outputLength);
      /* Add data written to the information to be returned */
      *OutputMessageLength += outputLength;
    }
  }

  return error_status;
}

/**
  * @brief  Compares two buffers.
  * @param  pBuffer, pBuffer1: buffers to be compared.
  * @param  BufferLength: buffer's length
  * @retval PASSED: pBuffer identical to pBuffer1
  *         FAILED: pBuffer differs from pBuffer1
  */
TestStatus Buffercmp(const uint8_t* pBuffer, uint8_t* pBuffer1, uint16_t BufferLength)
{
  while (BufferLength--)
  {
    if (*pBuffer != *pBuffer1)
    {
      return FAILED;
    }

    pBuffer++;
    pBuffer1++;
  }

  return PASSED;
}

void st_aes_cbc(void)
{
      /*!< At this stage the microcontroller clock setting is already configured,
       this is done through SystemInit() function which is called from startup
       file before to branch to application main.
       To reconfigure the default setting of SystemInit() function, refer to
       system_stm32f10x.c, system_stm32l1xx.c, system_stm32f0xx.c, 
       system_stm32f2xx.c, system_stm32f30x.c, system_stm32f37x.c, or
       system_stm32f4xx.c file depending on device.
     */
  int32_t status = AES_SUCCESS;

  /* DeInitialize STM32 Cryptographic Library */
   Crypto_DeInit();

   dbg_print("pkhoo: %s\n\r", __FUNCTION__);
  /* Encrypt DATA with AES in CBC mode */
  status = STM32_AES_CBC_Encrypt( (uint8_t *) Plaintext, PLAINTEXT_LENGTH, Key, IV, sizeof(IV), OutputMessage,
                            &OutputMessageLength);
  if (status == AES_SUCCESS)
  {
    if (Buffercmp(Expected_Ciphertext, OutputMessage, PLAINTEXT_LENGTH) == PASSED)
    {
      /* add application traintment in case of AES CBC encrption is passed */   
        dbg_print("pkhoo: %s - Buffercmp OK\n\r", __FUNCTION__);
            
    }
    else
    {
        dbg_print("pkhoo: %s - Buffercmp Failed\n\r", __FUNCTION__);
      /* add application traintment in case of AES CBC encrption is failed */
    }
  }
  else
  {
    dbg_print("pkhoo: %s - CBC Encrypt Failed\n\r", __FUNCTION__);
    /* Add application traintment in case of encryption/decryption not success possible values
       *  of status:
       * AES_ERR_BAD_CONTEXT, AES_ERR_BAD_PARAMETER, AES_ERR_BAD_INPUT_SIZE, AES_ERR_BAD_OPERATION
       */
  }
}
