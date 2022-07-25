# 1 "ex1_change_pin.c"
# 1 "<built-in>"
# 1 "<command-line>"
# 31 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 32 "<command-line>" 2
# 1 "ex1_change_pin.c"
# 11 "ex1_change_pin.c"
#include <Common.h>
# 11 "ex1_change_pin.c"
# 1 "/usr/local/include/Common.h" 1 3
# 33 "/usr/local/include/Common.h" 3
#include "wintypes.h"
# 33 "/usr/local/include/Common.h" 3
# 1 "/usr/local/include/wintypes.h" 1 3
# 9 "/usr/local/include/wintypes.h" 3
       



# 12 "/usr/local/include/wintypes.h" 3
typedef unsigned long DWORD;



typedef long LONG;



typedef unsigned char BYTE;



typedef int BOOL;



typedef BYTE* PBYTE;



typedef BYTE* LPBYTE;



typedef void* PVOID;
# 34 "/usr/local/include/Common.h" 2 3
#include <rtpkcs11.h>
# 34 "/usr/local/include/Common.h" 3
# 1 "/usr/local/include/rtpkcs11.h" 1 3
# 12 "/usr/local/include/rtpkcs11.h" 3
#include "cryptoki.h"
# 12 "/usr/local/include/rtpkcs11.h" 3
# 1 "/usr/local/include/cryptoki.h" 1 3
# 80 "/usr/local/include/cryptoki.h" 3
#include "pkcs11.h"
# 80 "/usr/local/include/cryptoki.h" 3
# 1 "/usr/local/include/pkcs11.h" 1 3
# 226 "/usr/local/include/pkcs11.h" 3
#include "pkcs11t.h"
# 226 "/usr/local/include/pkcs11.h" 3
# 1 "/usr/local/include/pkcs11t.h" 1 3
# 44 "/usr/local/include/pkcs11t.h" 3
typedef unsigned char CK_BYTE;


typedef CK_BYTE CK_CHAR;


typedef CK_BYTE CK_UTF8CHAR;


typedef CK_BYTE CK_BBOOL;


typedef unsigned long int CK_ULONG;



typedef long int CK_LONG;


typedef CK_ULONG CK_FLAGS;







typedef CK_BYTE * CK_BYTE_PTR;
typedef CK_CHAR * CK_CHAR_PTR;
typedef CK_UTF8CHAR * CK_UTF8CHAR_PTR;
typedef CK_ULONG * CK_ULONG_PTR;
typedef void * CK_VOID_PTR;


typedef CK_VOID_PTR * CK_VOID_PTR_PTR;







typedef struct CK_VERSION {
  CK_BYTE major;
  CK_BYTE minor;
} CK_VERSION;

typedef CK_VERSION * CK_VERSION_PTR;


typedef struct CK_INFO {


  CK_VERSION cryptokiVersion;
  CK_UTF8CHAR manufacturerID[32];
  CK_FLAGS flags;


  CK_UTF8CHAR libraryDescription[32];
  CK_VERSION libraryVersion;
} CK_INFO;

typedef CK_INFO * CK_INFO_PTR;






typedef CK_ULONG CK_NOTIFICATION;






typedef CK_ULONG CK_SLOT_ID;

typedef CK_SLOT_ID * CK_SLOT_ID_PTR;



typedef struct CK_SLOT_INFO {


  CK_UTF8CHAR slotDescription[64];
  CK_UTF8CHAR manufacturerID[32];
  CK_FLAGS flags;


  CK_VERSION hardwareVersion;
  CK_VERSION firmwareVersion;
} CK_SLOT_INFO;
# 145 "/usr/local/include/pkcs11t.h" 3
typedef CK_SLOT_INFO * CK_SLOT_INFO_PTR;



typedef struct CK_TOKEN_INFO {


  CK_UTF8CHAR label[32];
  CK_UTF8CHAR manufacturerID[32];
  CK_UTF8CHAR model[16];
  CK_CHAR serialNumber[16];
  CK_FLAGS flags;




  CK_ULONG ulMaxSessionCount;
  CK_ULONG ulSessionCount;
  CK_ULONG ulMaxRwSessionCount;
  CK_ULONG ulRwSessionCount;
  CK_ULONG ulMaxPinLen;
  CK_ULONG ulMinPinLen;
  CK_ULONG ulTotalPublicMemory;
  CK_ULONG ulFreePublicMemory;
  CK_ULONG ulTotalPrivateMemory;
  CK_ULONG ulFreePrivateMemory;



  CK_VERSION hardwareVersion;
  CK_VERSION firmwareVersion;
  CK_CHAR utcTime[16];
} CK_TOKEN_INFO;
# 268 "/usr/local/include/pkcs11t.h" 3
typedef CK_TOKEN_INFO * CK_TOKEN_INFO_PTR;




typedef CK_ULONG CK_SESSION_HANDLE;

typedef CK_SESSION_HANDLE * CK_SESSION_HANDLE_PTR;





typedef CK_ULONG CK_USER_TYPE;
# 292 "/usr/local/include/pkcs11t.h" 3
typedef CK_ULONG CK_STATE;
# 301 "/usr/local/include/pkcs11t.h" 3
typedef struct CK_SESSION_INFO {
  CK_SLOT_ID slotID;
  CK_STATE state;
  CK_FLAGS flags;



  CK_ULONG ulDeviceError;
} CK_SESSION_INFO;







typedef CK_SESSION_INFO * CK_SESSION_INFO_PTR;




typedef CK_ULONG CK_OBJECT_HANDLE;

typedef CK_OBJECT_HANDLE * CK_OBJECT_HANDLE_PTR;







typedef CK_ULONG CK_OBJECT_CLASS;
# 352 "/usr/local/include/pkcs11t.h" 3
typedef CK_OBJECT_CLASS * CK_OBJECT_CLASS_PTR;




typedef CK_ULONG CK_HW_FEATURE_TYPE;
# 368 "/usr/local/include/pkcs11t.h" 3
typedef CK_ULONG CK_KEY_TYPE;
# 425 "/usr/local/include/pkcs11t.h" 3
typedef CK_ULONG CK_CERTIFICATE_TYPE;
# 440 "/usr/local/include/pkcs11t.h" 3
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
# 606 "/usr/local/include/pkcs11t.h" 3
typedef struct CK_ATTRIBUTE {
  CK_ATTRIBUTE_TYPE type;
  CK_VOID_PTR pValue;


  CK_ULONG ulValueLen;
} CK_ATTRIBUTE;

typedef CK_ATTRIBUTE * CK_ATTRIBUTE_PTR;



typedef struct CK_DATE{
  CK_CHAR year[4];
  CK_CHAR month[2];
  CK_CHAR day[2];
} CK_DATE;






typedef CK_ULONG CK_MECHANISM_TYPE;
# 998 "/usr/local/include/pkcs11t.h" 3
typedef CK_MECHANISM_TYPE * CK_MECHANISM_TYPE_PTR;




typedef struct CK_MECHANISM {
  CK_MECHANISM_TYPE mechanism;
  CK_VOID_PTR pParameter;



  CK_ULONG ulParameterLen;
} CK_MECHANISM;

typedef CK_MECHANISM * CK_MECHANISM_PTR;




typedef struct CK_MECHANISM_INFO {
    CK_ULONG ulMinKeySize;
    CK_ULONG ulMaxKeySize;
    CK_FLAGS flags;
} CK_MECHANISM_INFO;
# 1058 "/usr/local/include/pkcs11t.h" 3
typedef CK_MECHANISM_INFO * CK_MECHANISM_INFO_PTR;





typedef CK_ULONG CK_RV;
# 1204 "/usr/local/include/pkcs11t.h" 3
typedef CK_RV ( * CK_NOTIFY)(
  CK_SESSION_HANDLE hSession,
  CK_NOTIFICATION event,
  CK_VOID_PTR pApplication
);






typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;

typedef CK_FUNCTION_LIST * CK_FUNCTION_LIST_PTR;

typedef CK_FUNCTION_LIST_PTR * CK_FUNCTION_LIST_PTR_PTR;




typedef CK_RV ( * CK_CREATEMUTEX)(
  CK_VOID_PTR_PTR ppMutex
);




typedef CK_RV ( * CK_DESTROYMUTEX)(
  CK_VOID_PTR pMutex
);



typedef CK_RV ( * CK_LOCKMUTEX)(
  CK_VOID_PTR pMutex
);




typedef CK_RV ( * CK_UNLOCKMUTEX)(
  CK_VOID_PTR pMutex
);




typedef struct CK_C_INITIALIZE_ARGS {
  CK_CREATEMUTEX CreateMutex;
  CK_DESTROYMUTEX DestroyMutex;
  CK_LOCKMUTEX LockMutex;
  CK_UNLOCKMUTEX UnlockMutex;
  CK_FLAGS flags;
  CK_VOID_PTR pReserved;
} CK_C_INITIALIZE_ARGS;







typedef CK_C_INITIALIZE_ARGS * CK_C_INITIALIZE_ARGS_PTR;
# 1279 "/usr/local/include/pkcs11t.h" 3
typedef CK_ULONG CK_RSA_PKCS_MGF_TYPE;

typedef CK_RSA_PKCS_MGF_TYPE * CK_RSA_PKCS_MGF_TYPE_PTR;
# 1297 "/usr/local/include/pkcs11t.h" 3
typedef CK_ULONG CK_RSA_PKCS_OAEP_SOURCE_TYPE;

typedef CK_RSA_PKCS_OAEP_SOURCE_TYPE * CK_RSA_PKCS_OAEP_SOURCE_TYPE_PTR;







typedef struct CK_RSA_PKCS_OAEP_PARAMS {
        CK_MECHANISM_TYPE hashAlg;
        CK_RSA_PKCS_MGF_TYPE mgf;
        CK_RSA_PKCS_OAEP_SOURCE_TYPE source;
        CK_VOID_PTR pSourceData;
        CK_ULONG ulSourceDataLen;
} CK_RSA_PKCS_OAEP_PARAMS;

typedef CK_RSA_PKCS_OAEP_PARAMS * CK_RSA_PKCS_OAEP_PARAMS_PTR;




typedef struct CK_RSA_PKCS_PSS_PARAMS {
        CK_MECHANISM_TYPE hashAlg;
        CK_RSA_PKCS_MGF_TYPE mgf;
        CK_ULONG sLen;
} CK_RSA_PKCS_PSS_PARAMS;

typedef CK_RSA_PKCS_PSS_PARAMS * CK_RSA_PKCS_PSS_PARAMS_PTR;


typedef CK_ULONG CK_EC_KDF_TYPE;
# 1340 "/usr/local/include/pkcs11t.h" 3
typedef struct CK_ECDH1_DERIVE_PARAMS {
  CK_EC_KDF_TYPE kdf;
  CK_ULONG ulSharedDataLen;
  CK_BYTE_PTR pSharedData;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
} CK_ECDH1_DERIVE_PARAMS;

typedef CK_ECDH1_DERIVE_PARAMS * CK_ECDH1_DERIVE_PARAMS_PTR;





typedef struct CK_ECDH2_DERIVE_PARAMS {
  CK_EC_KDF_TYPE kdf;
  CK_ULONG ulSharedDataLen;
  CK_BYTE_PTR pSharedData;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPrivateDataLen;
  CK_OBJECT_HANDLE hPrivateData;
  CK_ULONG ulPublicDataLen2;
  CK_BYTE_PTR pPublicData2;
} CK_ECDH2_DERIVE_PARAMS;

typedef CK_ECDH2_DERIVE_PARAMS * CK_ECDH2_DERIVE_PARAMS_PTR;

typedef struct CK_ECMQV_DERIVE_PARAMS {
  CK_EC_KDF_TYPE kdf;
  CK_ULONG ulSharedDataLen;
  CK_BYTE_PTR pSharedData;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPrivateDataLen;
  CK_OBJECT_HANDLE hPrivateData;
  CK_ULONG ulPublicDataLen2;
  CK_BYTE_PTR pPublicData2;
  CK_OBJECT_HANDLE publicKey;
} CK_ECMQV_DERIVE_PARAMS;

typedef CK_ECMQV_DERIVE_PARAMS * CK_ECMQV_DERIVE_PARAMS_PTR;



typedef CK_ULONG CK_X9_42_DH_KDF_TYPE;
typedef CK_X9_42_DH_KDF_TYPE * CK_X9_42_DH_KDF_TYPE_PTR;
# 1397 "/usr/local/include/pkcs11t.h" 3
typedef struct CK_X9_42_DH1_DERIVE_PARAMS {
  CK_X9_42_DH_KDF_TYPE kdf;
  CK_ULONG ulOtherInfoLen;
  CK_BYTE_PTR pOtherInfo;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
} CK_X9_42_DH1_DERIVE_PARAMS;

typedef struct CK_X9_42_DH1_DERIVE_PARAMS * CK_X9_42_DH1_DERIVE_PARAMS_PTR;





typedef struct CK_X9_42_DH2_DERIVE_PARAMS {
  CK_X9_42_DH_KDF_TYPE kdf;
  CK_ULONG ulOtherInfoLen;
  CK_BYTE_PTR pOtherInfo;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPrivateDataLen;
  CK_OBJECT_HANDLE hPrivateData;
  CK_ULONG ulPublicDataLen2;
  CK_BYTE_PTR pPublicData2;
} CK_X9_42_DH2_DERIVE_PARAMS;

typedef CK_X9_42_DH2_DERIVE_PARAMS * CK_X9_42_DH2_DERIVE_PARAMS_PTR;

typedef struct CK_X9_42_MQV_DERIVE_PARAMS {
  CK_X9_42_DH_KDF_TYPE kdf;
  CK_ULONG ulOtherInfoLen;
  CK_BYTE_PTR pOtherInfo;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPrivateDataLen;
  CK_OBJECT_HANDLE hPrivateData;
  CK_ULONG ulPublicDataLen2;
  CK_BYTE_PTR pPublicData2;
  CK_OBJECT_HANDLE publicKey;
} CK_X9_42_MQV_DERIVE_PARAMS;

typedef CK_X9_42_MQV_DERIVE_PARAMS * CK_X9_42_MQV_DERIVE_PARAMS_PTR;




typedef struct CK_KEA_DERIVE_PARAMS {
  CK_BBOOL isSender;
  CK_ULONG ulRandomLen;
  CK_BYTE_PTR pRandomA;
  CK_BYTE_PTR pRandomB;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
} CK_KEA_DERIVE_PARAMS;

typedef CK_KEA_DERIVE_PARAMS * CK_KEA_DERIVE_PARAMS_PTR;





typedef CK_ULONG CK_RC2_PARAMS;

typedef CK_RC2_PARAMS * CK_RC2_PARAMS_PTR;




typedef struct CK_RC2_CBC_PARAMS {


  CK_ULONG ulEffectiveBits;

  CK_BYTE iv[8];
} CK_RC2_CBC_PARAMS;

typedef CK_RC2_CBC_PARAMS * CK_RC2_CBC_PARAMS_PTR;





typedef struct CK_RC2_MAC_GENERAL_PARAMS {
  CK_ULONG ulEffectiveBits;
  CK_ULONG ulMacLength;
} CK_RC2_MAC_GENERAL_PARAMS;

typedef CK_RC2_MAC_GENERAL_PARAMS *
  CK_RC2_MAC_GENERAL_PARAMS_PTR;





typedef struct CK_RC5_PARAMS {
  CK_ULONG ulWordsize;
  CK_ULONG ulRounds;
} CK_RC5_PARAMS;

typedef CK_RC5_PARAMS * CK_RC5_PARAMS_PTR;





typedef struct CK_RC5_CBC_PARAMS {
  CK_ULONG ulWordsize;
  CK_ULONG ulRounds;
  CK_BYTE_PTR pIv;
  CK_ULONG ulIvLen;
} CK_RC5_CBC_PARAMS;

typedef CK_RC5_CBC_PARAMS * CK_RC5_CBC_PARAMS_PTR;





typedef struct CK_RC5_MAC_GENERAL_PARAMS {
  CK_ULONG ulWordsize;
  CK_ULONG ulRounds;
  CK_ULONG ulMacLength;
} CK_RC5_MAC_GENERAL_PARAMS;

typedef CK_RC5_MAC_GENERAL_PARAMS *
  CK_RC5_MAC_GENERAL_PARAMS_PTR;






typedef CK_ULONG CK_MAC_GENERAL_PARAMS;

typedef CK_MAC_GENERAL_PARAMS * CK_MAC_GENERAL_PARAMS_PTR;


typedef struct CK_DES_CBC_ENCRYPT_DATA_PARAMS {
  CK_BYTE iv[8];
  CK_BYTE_PTR pData;
  CK_ULONG length;
} CK_DES_CBC_ENCRYPT_DATA_PARAMS;

typedef CK_DES_CBC_ENCRYPT_DATA_PARAMS * CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR;

typedef struct CK_AES_CBC_ENCRYPT_DATA_PARAMS {
  CK_BYTE iv[16];
  CK_BYTE_PTR pData;
  CK_ULONG length;
} CK_AES_CBC_ENCRYPT_DATA_PARAMS;

typedef CK_AES_CBC_ENCRYPT_DATA_PARAMS * CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR;




typedef struct CK_SKIPJACK_PRIVATE_WRAP_PARAMS {
  CK_ULONG ulPasswordLen;
  CK_BYTE_PTR pPassword;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPAndGLen;
  CK_ULONG ulQLen;
  CK_ULONG ulRandomLen;
  CK_BYTE_PTR pRandomA;
  CK_BYTE_PTR pPrimeP;
  CK_BYTE_PTR pBaseG;
  CK_BYTE_PTR pSubprimeQ;
} CK_SKIPJACK_PRIVATE_WRAP_PARAMS;

typedef CK_SKIPJACK_PRIVATE_WRAP_PARAMS *
  CK_SKIPJACK_PRIVATE_WRAP_PTR;





typedef struct CK_SKIPJACK_RELAYX_PARAMS {
  CK_ULONG ulOldWrappedXLen;
  CK_BYTE_PTR pOldWrappedX;
  CK_ULONG ulOldPasswordLen;
  CK_BYTE_PTR pOldPassword;
  CK_ULONG ulOldPublicDataLen;
  CK_BYTE_PTR pOldPublicData;
  CK_ULONG ulOldRandomLen;
  CK_BYTE_PTR pOldRandomA;
  CK_ULONG ulNewPasswordLen;
  CK_BYTE_PTR pNewPassword;
  CK_ULONG ulNewPublicDataLen;
  CK_BYTE_PTR pNewPublicData;
  CK_ULONG ulNewRandomLen;
  CK_BYTE_PTR pNewRandomA;
} CK_SKIPJACK_RELAYX_PARAMS;

typedef CK_SKIPJACK_RELAYX_PARAMS *
  CK_SKIPJACK_RELAYX_PARAMS_PTR;


typedef struct CK_PBE_PARAMS {
  CK_BYTE_PTR pInitVector;
  CK_UTF8CHAR_PTR pPassword;
  CK_ULONG ulPasswordLen;
  CK_BYTE_PTR pSalt;
  CK_ULONG ulSaltLen;
  CK_ULONG ulIteration;
} CK_PBE_PARAMS;

typedef CK_PBE_PARAMS * CK_PBE_PARAMS_PTR;





typedef struct CK_KEY_WRAP_SET_OAEP_PARAMS {
  CK_BYTE bBC;
  CK_BYTE_PTR pX;
  CK_ULONG ulXLen;
} CK_KEY_WRAP_SET_OAEP_PARAMS;

typedef CK_KEY_WRAP_SET_OAEP_PARAMS *
  CK_KEY_WRAP_SET_OAEP_PARAMS_PTR;


typedef struct CK_SSL3_RANDOM_DATA {
  CK_BYTE_PTR pClientRandom;
  CK_ULONG ulClientRandomLen;
  CK_BYTE_PTR pServerRandom;
  CK_ULONG ulServerRandomLen;
} CK_SSL3_RANDOM_DATA;


typedef struct CK_SSL3_MASTER_KEY_DERIVE_PARAMS {
  CK_SSL3_RANDOM_DATA RandomInfo;
  CK_VERSION_PTR pVersion;
} CK_SSL3_MASTER_KEY_DERIVE_PARAMS;

typedef struct CK_SSL3_MASTER_KEY_DERIVE_PARAMS *
  CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR;


typedef struct CK_SSL3_KEY_MAT_OUT {
  CK_OBJECT_HANDLE hClientMacSecret;
  CK_OBJECT_HANDLE hServerMacSecret;
  CK_OBJECT_HANDLE hClientKey;
  CK_OBJECT_HANDLE hServerKey;
  CK_BYTE_PTR pIVClient;
  CK_BYTE_PTR pIVServer;
} CK_SSL3_KEY_MAT_OUT;

typedef CK_SSL3_KEY_MAT_OUT * CK_SSL3_KEY_MAT_OUT_PTR;


typedef struct CK_SSL3_KEY_MAT_PARAMS {
  CK_ULONG ulMacSizeInBits;
  CK_ULONG ulKeySizeInBits;
  CK_ULONG ulIVSizeInBits;
  CK_BBOOL bIsExport;
  CK_SSL3_RANDOM_DATA RandomInfo;
  CK_SSL3_KEY_MAT_OUT_PTR pReturnedKeyMaterial;
} CK_SSL3_KEY_MAT_PARAMS;

typedef CK_SSL3_KEY_MAT_PARAMS * CK_SSL3_KEY_MAT_PARAMS_PTR;


typedef struct CK_TLS_PRF_PARAMS {
  CK_BYTE_PTR pSeed;
  CK_ULONG ulSeedLen;
  CK_BYTE_PTR pLabel;
  CK_ULONG ulLabelLen;
  CK_BYTE_PTR pOutput;
  CK_ULONG_PTR pulOutputLen;
} CK_TLS_PRF_PARAMS;

typedef CK_TLS_PRF_PARAMS * CK_TLS_PRF_PARAMS_PTR;


typedef struct CK_WTLS_RANDOM_DATA {
  CK_BYTE_PTR pClientRandom;
  CK_ULONG ulClientRandomLen;
  CK_BYTE_PTR pServerRandom;
  CK_ULONG ulServerRandomLen;
} CK_WTLS_RANDOM_DATA;

typedef CK_WTLS_RANDOM_DATA * CK_WTLS_RANDOM_DATA_PTR;

typedef struct CK_WTLS_MASTER_KEY_DERIVE_PARAMS {
  CK_MECHANISM_TYPE DigestMechanism;
  CK_WTLS_RANDOM_DATA RandomInfo;
  CK_BYTE_PTR pVersion;
} CK_WTLS_MASTER_KEY_DERIVE_PARAMS;

typedef CK_WTLS_MASTER_KEY_DERIVE_PARAMS *
  CK_WTLS_MASTER_KEY_DERIVE_PARAMS_PTR;

typedef struct CK_WTLS_PRF_PARAMS {
  CK_MECHANISM_TYPE DigestMechanism;
  CK_BYTE_PTR pSeed;
  CK_ULONG ulSeedLen;
  CK_BYTE_PTR pLabel;
  CK_ULONG ulLabelLen;
  CK_BYTE_PTR pOutput;
  CK_ULONG_PTR pulOutputLen;
} CK_WTLS_PRF_PARAMS;

typedef CK_WTLS_PRF_PARAMS * CK_WTLS_PRF_PARAMS_PTR;

typedef struct CK_WTLS_KEY_MAT_OUT {
  CK_OBJECT_HANDLE hMacSecret;
  CK_OBJECT_HANDLE hKey;
  CK_BYTE_PTR pIV;
} CK_WTLS_KEY_MAT_OUT;

typedef CK_WTLS_KEY_MAT_OUT * CK_WTLS_KEY_MAT_OUT_PTR;

typedef struct CK_WTLS_KEY_MAT_PARAMS {
  CK_MECHANISM_TYPE DigestMechanism;
  CK_ULONG ulMacSizeInBits;
  CK_ULONG ulKeySizeInBits;
  CK_ULONG ulIVSizeInBits;
  CK_ULONG ulSequenceNumber;
  CK_BBOOL bIsExport;
  CK_WTLS_RANDOM_DATA RandomInfo;
  CK_WTLS_KEY_MAT_OUT_PTR pReturnedKeyMaterial;
} CK_WTLS_KEY_MAT_PARAMS;

typedef CK_WTLS_KEY_MAT_PARAMS * CK_WTLS_KEY_MAT_PARAMS_PTR;


typedef struct CK_CMS_SIG_PARAMS {
  CK_OBJECT_HANDLE certificateHandle;
  CK_MECHANISM_PTR pSigningMechanism;
  CK_MECHANISM_PTR pDigestMechanism;
  CK_UTF8CHAR_PTR pContentType;
  CK_BYTE_PTR pRequestedAttributes;
  CK_ULONG ulRequestedAttributesLen;
  CK_BYTE_PTR pRequiredAttributes;
  CK_ULONG ulRequiredAttributesLen;
} CK_CMS_SIG_PARAMS;

typedef CK_CMS_SIG_PARAMS * CK_CMS_SIG_PARAMS_PTR;

typedef struct CK_KEY_DERIVATION_STRING_DATA {
  CK_BYTE_PTR pData;
  CK_ULONG ulLen;
} CK_KEY_DERIVATION_STRING_DATA;

typedef CK_KEY_DERIVATION_STRING_DATA *
  CK_KEY_DERIVATION_STRING_DATA_PTR;







typedef CK_ULONG CK_EXTRACT_PARAMS;

typedef CK_EXTRACT_PARAMS * CK_EXTRACT_PARAMS_PTR;





typedef CK_ULONG CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE;

typedef CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE * CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE_PTR;
# 1772 "/usr/local/include/pkcs11t.h" 3
typedef CK_ULONG CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE;

typedef CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE * CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE_PTR;







typedef struct CK_PKCS5_PBKD2_PARAMS {
        CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE saltSource;
        CK_VOID_PTR pSaltSourceData;
        CK_ULONG ulSaltSourceDataLen;
        CK_ULONG iterations;
        CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE prf;
        CK_VOID_PTR pPrfData;
        CK_ULONG ulPrfDataLen;
        CK_UTF8CHAR_PTR pPassword;
        CK_ULONG_PTR ulPasswordLen;
} CK_PKCS5_PBKD2_PARAMS;

typedef CK_PKCS5_PBKD2_PARAMS * CK_PKCS5_PBKD2_PARAMS_PTR;



typedef CK_ULONG CK_OTP_PARAM_TYPE;
typedef CK_OTP_PARAM_TYPE CK_PARAM_TYPE;

typedef struct CK_OTP_PARAM {
    CK_OTP_PARAM_TYPE type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
} CK_OTP_PARAM;

typedef CK_OTP_PARAM * CK_OTP_PARAM_PTR;

typedef struct CK_OTP_PARAMS {
    CK_OTP_PARAM_PTR pParams;
    CK_ULONG ulCount;
} CK_OTP_PARAMS;

typedef CK_OTP_PARAMS * CK_OTP_PARAMS_PTR;

typedef struct CK_OTP_SIGNATURE_INFO {
    CK_OTP_PARAM_PTR pParams;
    CK_ULONG ulCount;
} CK_OTP_SIGNATURE_INFO;

typedef CK_OTP_SIGNATURE_INFO * CK_OTP_SIGNATURE_INFO_PTR;
# 1842 "/usr/local/include/pkcs11t.h" 3
typedef struct CK_KIP_PARAMS {
    CK_MECHANISM_PTR pMechanism;
    CK_OBJECT_HANDLE hKey;
    CK_BYTE_PTR pSeed;
    CK_ULONG ulSeedLen;
} CK_KIP_PARAMS;

typedef CK_KIP_PARAMS * CK_KIP_PARAMS_PTR;


typedef struct CK_AES_CTR_PARAMS {
    CK_ULONG ulCounterBits;
    CK_BYTE cb[16];
} CK_AES_CTR_PARAMS;

typedef CK_AES_CTR_PARAMS * CK_AES_CTR_PARAMS_PTR;


typedef struct CK_CAMELLIA_CTR_PARAMS {
    CK_ULONG ulCounterBits;
    CK_BYTE cb[16];
} CK_CAMELLIA_CTR_PARAMS;

typedef CK_CAMELLIA_CTR_PARAMS * CK_CAMELLIA_CTR_PARAMS_PTR;


typedef struct CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS {
    CK_BYTE iv[16];
    CK_BYTE_PTR pData;
    CK_ULONG length;
} CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS;

typedef CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS * CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS_PTR;


typedef struct CK_ARIA_CBC_ENCRYPT_DATA_PARAMS {
    CK_BYTE iv[16];
    CK_BYTE_PTR pData;
    CK_ULONG length;
} CK_ARIA_CBC_ENCRYPT_DATA_PARAMS;

typedef CK_ARIA_CBC_ENCRYPT_DATA_PARAMS * CK_ARIA_CBC_ENCRYPT_DATA_PARAMS_PTR;
# 227 "/usr/local/include/pkcs11.h" 2 3
# 242 "/usr/local/include/pkcs11.h" 3
#include "pkcs11f.h"
# 242 "/usr/local/include/pkcs11.h" 3
# 1 "/usr/local/include/pkcs11f.h" 1 3
# 28 "/usr/local/include/pkcs11f.h" 3
extern CK_RV C_Initialize

(
  CK_VOID_PTR pInitArgs


);





extern CK_RV C_Finalize

(
  CK_VOID_PTR pReserved
);




extern CK_RV C_GetInfo

(
  CK_INFO_PTR pInfo
);




extern CK_RV C_GetFunctionList

(
  CK_FUNCTION_LIST_PTR_PTR ppFunctionList

);







extern CK_RV C_GetSlotList

(
  CK_BBOOL tokenPresent,
  CK_SLOT_ID_PTR pSlotList,
  CK_ULONG_PTR pulCount
);





extern CK_RV C_GetSlotInfo

(
  CK_SLOT_ID slotID,
  CK_SLOT_INFO_PTR pInfo
);





extern CK_RV C_GetTokenInfo

(
  CK_SLOT_ID slotID,
  CK_TOKEN_INFO_PTR pInfo
);





extern CK_RV C_GetMechanismList

(
  CK_SLOT_ID slotID,
  CK_MECHANISM_TYPE_PTR pMechanismList,
  CK_ULONG_PTR pulCount
);





extern CK_RV C_GetMechanismInfo

(
  CK_SLOT_ID slotID,
  CK_MECHANISM_TYPE type,
  CK_MECHANISM_INFO_PTR pInfo
);




extern CK_RV C_InitToken


(
  CK_SLOT_ID slotID,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG ulPinLen,
  CK_UTF8CHAR_PTR pLabel
);




extern CK_RV C_InitPIN

(
  CK_SESSION_HANDLE hSession,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG ulPinLen
);




extern CK_RV C_SetPIN

(
  CK_SESSION_HANDLE hSession,
  CK_UTF8CHAR_PTR pOldPin,
  CK_ULONG ulOldLen,
  CK_UTF8CHAR_PTR pNewPin,
  CK_ULONG ulNewLen
);
# 169 "/usr/local/include/pkcs11f.h" 3
extern CK_RV C_OpenSession

(
  CK_SLOT_ID slotID,
  CK_FLAGS flags,
  CK_VOID_PTR pApplication,
  CK_NOTIFY Notify,
  CK_SESSION_HANDLE_PTR phSession
);





extern CK_RV C_CloseSession

(
  CK_SESSION_HANDLE hSession
);




extern CK_RV C_CloseAllSessions

(
  CK_SLOT_ID slotID
);




extern CK_RV C_GetSessionInfo

(
  CK_SESSION_HANDLE hSession,
  CK_SESSION_INFO_PTR pInfo
);





extern CK_RV C_GetOperationState

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pOperationState,
  CK_ULONG_PTR pulOperationStateLen
);





extern CK_RV C_SetOperationState

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pOperationState,
  CK_ULONG ulOperationStateLen,
  CK_OBJECT_HANDLE hEncryptionKey,
  CK_OBJECT_HANDLE hAuthenticationKey
);




extern CK_RV C_Login

(
  CK_SESSION_HANDLE hSession,
  CK_USER_TYPE userType,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG ulPinLen
);




extern CK_RV C_Logout

(
  CK_SESSION_HANDLE hSession
);







extern CK_RV C_CreateObject

(
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount,
  CK_OBJECT_HANDLE_PTR phObject
);





extern CK_RV C_CopyObject

(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount,
  CK_OBJECT_HANDLE_PTR phNewObject
);




extern CK_RV C_DestroyObject

(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject
);




extern CK_RV C_GetObjectSize

(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ULONG_PTR pulSize
);





extern CK_RV C_GetAttributeValue

(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount
);





extern CK_RV C_SetAttributeValue

(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount
);





extern CK_RV C_FindObjectsInit

(
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount
);






extern CK_RV C_FindObjects

(
 CK_SESSION_HANDLE hSession,
 CK_OBJECT_HANDLE_PTR phObject,
 CK_ULONG ulMaxObjectCount,
 CK_ULONG_PTR pulObjectCount
);





extern CK_RV C_FindObjectsFinal

(
  CK_SESSION_HANDLE hSession
);







extern CK_RV C_EncryptInit

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
);




extern CK_RV C_Encrypt

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pEncryptedData,
  CK_ULONG_PTR pulEncryptedDataLen
);





extern CK_RV C_EncryptUpdate

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG_PTR pulEncryptedPartLen
);





extern CK_RV C_EncryptFinal

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pLastEncryptedPart,
  CK_ULONG_PTR pulLastEncryptedPartLen
);




extern CK_RV C_DecryptInit

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
);




extern CK_RV C_Decrypt

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedData,
  CK_ULONG ulEncryptedDataLen,
  CK_BYTE_PTR pData,
  CK_ULONG_PTR pulDataLen
);





extern CK_RV C_DecryptUpdate

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG ulEncryptedPartLen,
  CK_BYTE_PTR pPart,
  CK_ULONG_PTR pulPartLen
);





extern CK_RV C_DecryptFinal

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pLastPart,
  CK_ULONG_PTR pulLastPartLen
);







extern CK_RV C_DigestInit

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism
);




extern CK_RV C_Digest

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pDigest,
  CK_ULONG_PTR pulDigestLen
);





extern CK_RV C_DigestUpdate

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen
);






extern CK_RV C_DigestKey

(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hKey
);





extern CK_RV C_DigestFinal

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pDigest,
  CK_ULONG_PTR pulDigestLen
);
# 541 "/usr/local/include/pkcs11f.h" 3
extern CK_RV C_SignInit

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
);






extern CK_RV C_Sign

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen
);






extern CK_RV C_SignUpdate

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen
);





extern CK_RV C_SignFinal

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen
);





extern CK_RV C_SignRecoverInit

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
);





extern CK_RV C_SignRecover

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen
);
# 623 "/usr/local/include/pkcs11f.h" 3
extern CK_RV C_VerifyInit

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
);






extern CK_RV C_Verify

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pSignature,
  CK_ULONG ulSignatureLen
);






extern CK_RV C_VerifyUpdate

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen
);





extern CK_RV C_VerifyFinal

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSignature,
  CK_ULONG ulSignatureLen
);





extern CK_RV C_VerifyRecoverInit

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
);





extern CK_RV C_VerifyRecover

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSignature,
  CK_ULONG ulSignatureLen,
  CK_BYTE_PTR pData,
  CK_ULONG_PTR pulDataLen
);
# 704 "/usr/local/include/pkcs11f.h" 3
extern CK_RV C_DigestEncryptUpdate

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG_PTR pulEncryptedPartLen
);





extern CK_RV C_DecryptDigestUpdate

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG ulEncryptedPartLen,
  CK_BYTE_PTR pPart,
  CK_ULONG_PTR pulPartLen
);





extern CK_RV C_SignEncryptUpdate

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG_PTR pulEncryptedPartLen
);





extern CK_RV C_DecryptVerifyUpdate

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG ulEncryptedPartLen,
  CK_BYTE_PTR pPart,
  CK_ULONG_PTR pulPartLen
);
# 763 "/usr/local/include/pkcs11f.h" 3
extern CK_RV C_GenerateKey

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount,
  CK_OBJECT_HANDLE_PTR phKey
);





extern CK_RV C_GenerateKeyPair

(
  CK_SESSION_HANDLE hSession,

  CK_MECHANISM_PTR pMechanism,

  CK_ATTRIBUTE_PTR pPublicKeyTemplate,


  CK_ULONG ulPublicKeyAttributeCount,

  CK_ATTRIBUTE_PTR pPrivateKeyTemplate,


  CK_ULONG ulPrivateKeyAttributeCount,

  CK_OBJECT_HANDLE_PTR phPublicKey,


  CK_OBJECT_HANDLE_PTR phPrivateKey


);




extern CK_RV C_WrapKey

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hWrappingKey,
  CK_OBJECT_HANDLE hKey,
  CK_BYTE_PTR pWrappedKey,
  CK_ULONG_PTR pulWrappedKeyLen
);





extern CK_RV C_UnwrapKey

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hUnwrappingKey,
  CK_BYTE_PTR pWrappedKey,
  CK_ULONG ulWrappedKeyLen,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulAttributeCount,
  CK_OBJECT_HANDLE_PTR phKey
);





extern CK_RV C_DeriveKey

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hBaseKey,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulAttributeCount,
  CK_OBJECT_HANDLE_PTR phKey
);
# 855 "/usr/local/include/pkcs11f.h" 3
extern CK_RV C_SeedRandom

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSeed,
  CK_ULONG ulSeedLen
);




extern CK_RV C_GenerateRandom

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR RandomData,
  CK_ULONG ulRandomLen
);
# 882 "/usr/local/include/pkcs11f.h" 3
extern CK_RV C_GetFunctionStatus

(
  CK_SESSION_HANDLE hSession
);





extern CK_RV C_CancelFunction

(
  CK_SESSION_HANDLE hSession
);
# 905 "/usr/local/include/pkcs11f.h" 3
extern CK_RV C_WaitForSlotEvent

(
  CK_FLAGS flags,
  CK_SLOT_ID_PTR pSlot,
  CK_VOID_PTR pRserved
);
# 243 "/usr/local/include/pkcs11.h" 2 3
# 261 "/usr/local/include/pkcs11.h" 3
#include "pkcs11f.h"
# 261 "/usr/local/include/pkcs11.h" 3
# 1 "/usr/local/include/pkcs11f.h" 1 3
# 28 "/usr/local/include/pkcs11f.h" 3
typedef CK_RV ( * CK_C_Initialize)

(
  CK_VOID_PTR pInitArgs


);





typedef CK_RV ( * CK_C_Finalize)

(
  CK_VOID_PTR pReserved
);




typedef CK_RV ( * CK_C_GetInfo)

(
  CK_INFO_PTR pInfo
);




typedef CK_RV ( * CK_C_GetFunctionList)

(
  CK_FUNCTION_LIST_PTR_PTR ppFunctionList

);







typedef CK_RV ( * CK_C_GetSlotList)

(
  CK_BBOOL tokenPresent,
  CK_SLOT_ID_PTR pSlotList,
  CK_ULONG_PTR pulCount
);





typedef CK_RV ( * CK_C_GetSlotInfo)

(
  CK_SLOT_ID slotID,
  CK_SLOT_INFO_PTR pInfo
);





typedef CK_RV ( * CK_C_GetTokenInfo)

(
  CK_SLOT_ID slotID,
  CK_TOKEN_INFO_PTR pInfo
);





typedef CK_RV ( * CK_C_GetMechanismList)

(
  CK_SLOT_ID slotID,
  CK_MECHANISM_TYPE_PTR pMechanismList,
  CK_ULONG_PTR pulCount
);





typedef CK_RV ( * CK_C_GetMechanismInfo)

(
  CK_SLOT_ID slotID,
  CK_MECHANISM_TYPE type,
  CK_MECHANISM_INFO_PTR pInfo
);




typedef CK_RV ( * CK_C_InitToken)


(
  CK_SLOT_ID slotID,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG ulPinLen,
  CK_UTF8CHAR_PTR pLabel
);




typedef CK_RV ( * CK_C_InitPIN)

(
  CK_SESSION_HANDLE hSession,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG ulPinLen
);




typedef CK_RV ( * CK_C_SetPIN)

(
  CK_SESSION_HANDLE hSession,
  CK_UTF8CHAR_PTR pOldPin,
  CK_ULONG ulOldLen,
  CK_UTF8CHAR_PTR pNewPin,
  CK_ULONG ulNewLen
);
# 169 "/usr/local/include/pkcs11f.h" 3
typedef CK_RV ( * CK_C_OpenSession)

(
  CK_SLOT_ID slotID,
  CK_FLAGS flags,
  CK_VOID_PTR pApplication,
  CK_NOTIFY Notify,
  CK_SESSION_HANDLE_PTR phSession
);





typedef CK_RV ( * CK_C_CloseSession)

(
  CK_SESSION_HANDLE hSession
);




typedef CK_RV ( * CK_C_CloseAllSessions)

(
  CK_SLOT_ID slotID
);




typedef CK_RV ( * CK_C_GetSessionInfo)

(
  CK_SESSION_HANDLE hSession,
  CK_SESSION_INFO_PTR pInfo
);





typedef CK_RV ( * CK_C_GetOperationState)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pOperationState,
  CK_ULONG_PTR pulOperationStateLen
);





typedef CK_RV ( * CK_C_SetOperationState)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pOperationState,
  CK_ULONG ulOperationStateLen,
  CK_OBJECT_HANDLE hEncryptionKey,
  CK_OBJECT_HANDLE hAuthenticationKey
);




typedef CK_RV ( * CK_C_Login)

(
  CK_SESSION_HANDLE hSession,
  CK_USER_TYPE userType,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG ulPinLen
);




typedef CK_RV ( * CK_C_Logout)

(
  CK_SESSION_HANDLE hSession
);







typedef CK_RV ( * CK_C_CreateObject)

(
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount,
  CK_OBJECT_HANDLE_PTR phObject
);





typedef CK_RV ( * CK_C_CopyObject)

(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount,
  CK_OBJECT_HANDLE_PTR phNewObject
);




typedef CK_RV ( * CK_C_DestroyObject)

(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject
);




typedef CK_RV ( * CK_C_GetObjectSize)

(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ULONG_PTR pulSize
);





typedef CK_RV ( * CK_C_GetAttributeValue)

(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount
);





typedef CK_RV ( * CK_C_SetAttributeValue)

(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hObject,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount
);





typedef CK_RV ( * CK_C_FindObjectsInit)

(
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount
);






typedef CK_RV ( * CK_C_FindObjects)

(
 CK_SESSION_HANDLE hSession,
 CK_OBJECT_HANDLE_PTR phObject,
 CK_ULONG ulMaxObjectCount,
 CK_ULONG_PTR pulObjectCount
);





typedef CK_RV ( * CK_C_FindObjectsFinal)

(
  CK_SESSION_HANDLE hSession
);







typedef CK_RV ( * CK_C_EncryptInit)

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
);




typedef CK_RV ( * CK_C_Encrypt)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pEncryptedData,
  CK_ULONG_PTR pulEncryptedDataLen
);





typedef CK_RV ( * CK_C_EncryptUpdate)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG_PTR pulEncryptedPartLen
);





typedef CK_RV ( * CK_C_EncryptFinal)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pLastEncryptedPart,
  CK_ULONG_PTR pulLastEncryptedPartLen
);




typedef CK_RV ( * CK_C_DecryptInit)

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
);




typedef CK_RV ( * CK_C_Decrypt)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedData,
  CK_ULONG ulEncryptedDataLen,
  CK_BYTE_PTR pData,
  CK_ULONG_PTR pulDataLen
);





typedef CK_RV ( * CK_C_DecryptUpdate)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG ulEncryptedPartLen,
  CK_BYTE_PTR pPart,
  CK_ULONG_PTR pulPartLen
);





typedef CK_RV ( * CK_C_DecryptFinal)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pLastPart,
  CK_ULONG_PTR pulLastPartLen
);







typedef CK_RV ( * CK_C_DigestInit)

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism
);




typedef CK_RV ( * CK_C_Digest)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pDigest,
  CK_ULONG_PTR pulDigestLen
);





typedef CK_RV ( * CK_C_DigestUpdate)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen
);






typedef CK_RV ( * CK_C_DigestKey)

(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hKey
);





typedef CK_RV ( * CK_C_DigestFinal)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pDigest,
  CK_ULONG_PTR pulDigestLen
);
# 541 "/usr/local/include/pkcs11f.h" 3
typedef CK_RV ( * CK_C_SignInit)

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
);






typedef CK_RV ( * CK_C_Sign)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen
);






typedef CK_RV ( * CK_C_SignUpdate)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen
);





typedef CK_RV ( * CK_C_SignFinal)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen
);





typedef CK_RV ( * CK_C_SignRecoverInit)

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
);





typedef CK_RV ( * CK_C_SignRecover)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen
);
# 623 "/usr/local/include/pkcs11f.h" 3
typedef CK_RV ( * CK_C_VerifyInit)

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
);






typedef CK_RV ( * CK_C_Verify)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pSignature,
  CK_ULONG ulSignatureLen
);






typedef CK_RV ( * CK_C_VerifyUpdate)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen
);





typedef CK_RV ( * CK_C_VerifyFinal)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSignature,
  CK_ULONG ulSignatureLen
);





typedef CK_RV ( * CK_C_VerifyRecoverInit)

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
);





typedef CK_RV ( * CK_C_VerifyRecover)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSignature,
  CK_ULONG ulSignatureLen,
  CK_BYTE_PTR pData,
  CK_ULONG_PTR pulDataLen
);
# 704 "/usr/local/include/pkcs11f.h" 3
typedef CK_RV ( * CK_C_DigestEncryptUpdate)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG_PTR pulEncryptedPartLen
);





typedef CK_RV ( * CK_C_DecryptDigestUpdate)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG ulEncryptedPartLen,
  CK_BYTE_PTR pPart,
  CK_ULONG_PTR pulPartLen
);





typedef CK_RV ( * CK_C_SignEncryptUpdate)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pPart,
  CK_ULONG ulPartLen,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG_PTR pulEncryptedPartLen
);





typedef CK_RV ( * CK_C_DecryptVerifyUpdate)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pEncryptedPart,
  CK_ULONG ulEncryptedPartLen,
  CK_BYTE_PTR pPart,
  CK_ULONG_PTR pulPartLen
);
# 763 "/usr/local/include/pkcs11f.h" 3
typedef CK_RV ( * CK_C_GenerateKey)

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulCount,
  CK_OBJECT_HANDLE_PTR phKey
);





typedef CK_RV ( * CK_C_GenerateKeyPair)

(
  CK_SESSION_HANDLE hSession,

  CK_MECHANISM_PTR pMechanism,

  CK_ATTRIBUTE_PTR pPublicKeyTemplate,


  CK_ULONG ulPublicKeyAttributeCount,

  CK_ATTRIBUTE_PTR pPrivateKeyTemplate,


  CK_ULONG ulPrivateKeyAttributeCount,

  CK_OBJECT_HANDLE_PTR phPublicKey,


  CK_OBJECT_HANDLE_PTR phPrivateKey


);




typedef CK_RV ( * CK_C_WrapKey)

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hWrappingKey,
  CK_OBJECT_HANDLE hKey,
  CK_BYTE_PTR pWrappedKey,
  CK_ULONG_PTR pulWrappedKeyLen
);





typedef CK_RV ( * CK_C_UnwrapKey)

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hUnwrappingKey,
  CK_BYTE_PTR pWrappedKey,
  CK_ULONG ulWrappedKeyLen,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulAttributeCount,
  CK_OBJECT_HANDLE_PTR phKey
);





typedef CK_RV ( * CK_C_DeriveKey)

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hBaseKey,
  CK_ATTRIBUTE_PTR pTemplate,
  CK_ULONG ulAttributeCount,
  CK_OBJECT_HANDLE_PTR phKey
);
# 855 "/usr/local/include/pkcs11f.h" 3
typedef CK_RV ( * CK_C_SeedRandom)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pSeed,
  CK_ULONG ulSeedLen
);




typedef CK_RV ( * CK_C_GenerateRandom)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR RandomData,
  CK_ULONG ulRandomLen
);
# 882 "/usr/local/include/pkcs11f.h" 3
typedef CK_RV ( * CK_C_GetFunctionStatus)

(
  CK_SESSION_HANDLE hSession
);





typedef CK_RV ( * CK_C_CancelFunction)

(
  CK_SESSION_HANDLE hSession
);
# 905 "/usr/local/include/pkcs11f.h" 3
typedef CK_RV ( * CK_C_WaitForSlotEvent)

(
  CK_FLAGS flags,
  CK_SLOT_ID_PTR pSlot,
  CK_VOID_PTR pRserved
);
# 262 "/usr/local/include/pkcs11.h" 2 3
# 279 "/usr/local/include/pkcs11.h" 3
struct CK_FUNCTION_LIST {

  CK_VERSION version;




#include "pkcs11f.h"
# 286 "/usr/local/include/pkcs11.h" 3
# 1 "/usr/local/include/pkcs11f.h" 1 3
# 28 "/usr/local/include/pkcs11f.h" 3
CK_C_Initialize C_Initialize;
# 40 "/usr/local/include/pkcs11f.h" 3
CK_C_Finalize C_Finalize;
# 49 "/usr/local/include/pkcs11f.h" 3
CK_C_GetInfo C_GetInfo;
# 58 "/usr/local/include/pkcs11f.h" 3
CK_C_GetFunctionList C_GetFunctionList;
# 71 "/usr/local/include/pkcs11f.h" 3
CK_C_GetSlotList C_GetSlotList;
# 83 "/usr/local/include/pkcs11f.h" 3
CK_C_GetSlotInfo C_GetSlotInfo;
# 94 "/usr/local/include/pkcs11f.h" 3
CK_C_GetTokenInfo C_GetTokenInfo;
# 105 "/usr/local/include/pkcs11f.h" 3
CK_C_GetMechanismList C_GetMechanismList;
# 117 "/usr/local/include/pkcs11f.h" 3
CK_C_GetMechanismInfo C_GetMechanismInfo;
# 128 "/usr/local/include/pkcs11f.h" 3
CK_C_InitToken C_InitToken;
# 141 "/usr/local/include/pkcs11f.h" 3
CK_C_InitPIN C_InitPIN;
# 152 "/usr/local/include/pkcs11f.h" 3
CK_C_SetPIN C_SetPIN;
# 169 "/usr/local/include/pkcs11f.h" 3
CK_C_OpenSession C_OpenSession;
# 183 "/usr/local/include/pkcs11f.h" 3
CK_C_CloseSession C_CloseSession;
# 192 "/usr/local/include/pkcs11f.h" 3
CK_C_CloseAllSessions C_CloseAllSessions;
# 201 "/usr/local/include/pkcs11f.h" 3
CK_C_GetSessionInfo C_GetSessionInfo;
# 212 "/usr/local/include/pkcs11f.h" 3
CK_C_GetOperationState C_GetOperationState;
# 224 "/usr/local/include/pkcs11f.h" 3
CK_C_SetOperationState C_SetOperationState;
# 237 "/usr/local/include/pkcs11f.h" 3
CK_C_Login C_Login;
# 249 "/usr/local/include/pkcs11f.h" 3
CK_C_Logout C_Logout;
# 261 "/usr/local/include/pkcs11f.h" 3
CK_C_CreateObject C_CreateObject;
# 274 "/usr/local/include/pkcs11f.h" 3
CK_C_CopyObject C_CopyObject;
# 287 "/usr/local/include/pkcs11f.h" 3
CK_C_DestroyObject C_DestroyObject;
# 297 "/usr/local/include/pkcs11f.h" 3
CK_C_GetObjectSize C_GetObjectSize;
# 309 "/usr/local/include/pkcs11f.h" 3
CK_C_GetAttributeValue C_GetAttributeValue;
# 322 "/usr/local/include/pkcs11f.h" 3
CK_C_SetAttributeValue C_SetAttributeValue;
# 335 "/usr/local/include/pkcs11f.h" 3
CK_C_FindObjectsInit C_FindObjectsInit;
# 348 "/usr/local/include/pkcs11f.h" 3
CK_C_FindObjects C_FindObjects;
# 361 "/usr/local/include/pkcs11f.h" 3
CK_C_FindObjectsFinal C_FindObjectsFinal;
# 373 "/usr/local/include/pkcs11f.h" 3
CK_C_EncryptInit C_EncryptInit;
# 384 "/usr/local/include/pkcs11f.h" 3
CK_C_Encrypt C_Encrypt;
# 398 "/usr/local/include/pkcs11f.h" 3
CK_C_EncryptUpdate C_EncryptUpdate;
# 412 "/usr/local/include/pkcs11f.h" 3
CK_C_EncryptFinal C_EncryptFinal;
# 423 "/usr/local/include/pkcs11f.h" 3
CK_C_DecryptInit C_DecryptInit;
# 434 "/usr/local/include/pkcs11f.h" 3
CK_C_Decrypt C_Decrypt;
# 448 "/usr/local/include/pkcs11f.h" 3
CK_C_DecryptUpdate C_DecryptUpdate;
# 462 "/usr/local/include/pkcs11f.h" 3
CK_C_DecryptFinal C_DecryptFinal;
# 476 "/usr/local/include/pkcs11f.h" 3
CK_C_DigestInit C_DigestInit;
# 486 "/usr/local/include/pkcs11f.h" 3
CK_C_Digest C_Digest;
# 500 "/usr/local/include/pkcs11f.h" 3
CK_C_DigestUpdate C_DigestUpdate;
# 513 "/usr/local/include/pkcs11f.h" 3
CK_C_DigestKey C_DigestKey;
# 524 "/usr/local/include/pkcs11f.h" 3
CK_C_DigestFinal C_DigestFinal;
# 541 "/usr/local/include/pkcs11f.h" 3
CK_C_SignInit C_SignInit;
# 554 "/usr/local/include/pkcs11f.h" 3
CK_C_Sign C_Sign;
# 569 "/usr/local/include/pkcs11f.h" 3
CK_C_SignUpdate C_SignUpdate;
# 581 "/usr/local/include/pkcs11f.h" 3
CK_C_SignFinal C_SignFinal;
# 593 "/usr/local/include/pkcs11f.h" 3
CK_C_SignRecoverInit C_SignRecoverInit;
# 605 "/usr/local/include/pkcs11f.h" 3
CK_C_SignRecover C_SignRecover;
# 623 "/usr/local/include/pkcs11f.h" 3
CK_C_VerifyInit C_VerifyInit;
# 636 "/usr/local/include/pkcs11f.h" 3
CK_C_Verify C_Verify;
# 651 "/usr/local/include/pkcs11f.h" 3
CK_C_VerifyUpdate C_VerifyUpdate;
# 663 "/usr/local/include/pkcs11f.h" 3
CK_C_VerifyFinal C_VerifyFinal;
# 675 "/usr/local/include/pkcs11f.h" 3
CK_C_VerifyRecoverInit C_VerifyRecoverInit;
# 687 "/usr/local/include/pkcs11f.h" 3
CK_C_VerifyRecover C_VerifyRecover;
# 704 "/usr/local/include/pkcs11f.h" 3
CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
# 718 "/usr/local/include/pkcs11f.h" 3
CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
# 732 "/usr/local/include/pkcs11f.h" 3
CK_C_SignEncryptUpdate C_SignEncryptUpdate;
# 746 "/usr/local/include/pkcs11f.h" 3
CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
# 763 "/usr/local/include/pkcs11f.h" 3
CK_C_GenerateKey C_GenerateKey;
# 777 "/usr/local/include/pkcs11f.h" 3
CK_C_GenerateKeyPair C_GenerateKeyPair;
# 805 "/usr/local/include/pkcs11f.h" 3
CK_C_WrapKey C_WrapKey;
# 820 "/usr/local/include/pkcs11f.h" 3
CK_C_UnwrapKey C_UnwrapKey;
# 837 "/usr/local/include/pkcs11f.h" 3
CK_C_DeriveKey C_DeriveKey;
# 855 "/usr/local/include/pkcs11f.h" 3
CK_C_SeedRandom C_SeedRandom;
# 866 "/usr/local/include/pkcs11f.h" 3
CK_C_GenerateRandom C_GenerateRandom;
# 882 "/usr/local/include/pkcs11f.h" 3
CK_C_GetFunctionStatus C_GetFunctionStatus;
# 892 "/usr/local/include/pkcs11f.h" 3
CK_C_CancelFunction C_CancelFunction;
# 905 "/usr/local/include/pkcs11f.h" 3
CK_C_WaitForSlotEvent C_WaitForSlotEvent;
# 287 "/usr/local/include/pkcs11.h" 2 3

};
# 81 "/usr/local/include/cryptoki.h" 2 3
# 13 "/usr/local/include/rtpkcs11.h" 2 3
# 22 "/usr/local/include/rtpkcs11.h" 3
#include "rtpkcs11t.h"
# 22 "/usr/local/include/rtpkcs11.h" 3
# 1 "/usr/local/include/rtpkcs11t.h" 1 3
# 97 "/usr/local/include/rtpkcs11t.h" 3
typedef struct CK_GOSTR3410_KEY_WRAP_PARAMS {
  CK_BYTE_PTR pWrapOID;
  CK_ULONG ulWrapOIDLen;
  CK_BYTE_PTR pUKM;
  CK_ULONG ulUKMLen;
  CK_OBJECT_HANDLE hKey;
} CK_GOSTR3410_KEY_WRAP_PARAMS;

typedef CK_GOSTR3410_KEY_WRAP_PARAMS * CK_GOSTR3410_KEY_WRAP_PARAMS_PTR;

typedef struct CK_GOSTR3410_DERIVE_PARAMS {
  CK_EC_KDF_TYPE kdf;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pUKM;
  CK_ULONG ulUKMLen;
} CK_GOSTR3410_DERIVE_PARAMS;

typedef CK_GOSTR3410_DERIVE_PARAMS * CK_GOSTR3410_DERIVE_PARAMS_PTR;
# 126 "/usr/local/include/rtpkcs11t.h" 3
typedef struct CK_FUNCTION_LIST_EXTENDED CK_FUNCTION_LIST_EXTENDED;

typedef CK_FUNCTION_LIST_EXTENDED * CK_FUNCTION_LIST_EXTENDED_PTR;

typedef CK_FUNCTION_LIST_EXTENDED_PTR * CK_FUNCTION_LIST_EXTENDED_PTR_PTR;
# 181 "/usr/local/include/rtpkcs11t.h" 3
typedef struct CK_RUTOKEN_INIT_PARAM {
  CK_ULONG ulSizeofThisStructure;
  CK_ULONG UseRepairMode;
  CK_BYTE_PTR pNewAdminPin;
  CK_ULONG ulNewAdminPinLen;
  CK_BYTE_PTR pNewUserPin;
  CK_ULONG ulNewUserPinLen;





  CK_FLAGS ChangeUserPINPolicy;
  CK_ULONG ulMinAdminPinLen;
  CK_ULONG ulMinUserPinLen;
  CK_ULONG ulMaxAdminRetryCount;
  CK_ULONG ulMaxUserRetryCount;
  CK_BYTE_PTR pTokenLabel;
  CK_ULONG ulLabelLen;
  CK_ULONG ulSmMode;
} CK_RUTOKEN_INIT_PARAM;

typedef CK_RUTOKEN_INIT_PARAM * CK_RUTOKEN_INIT_PARAM_PTR;
# 228 "/usr/local/include/rtpkcs11t.h" 3
typedef struct CK_VENDOR_RESTORE_FACTORY_DEFAULTS_PARAMS {
  CK_ULONG ulSizeofThisStructure;
  CK_BYTE_PTR pAdminPin;
  CK_ULONG ulAdminPinLen;
  CK_RUTOKEN_INIT_PARAM_PTR pInitParam;
  CK_BYTE_PTR pNewEmitentKey;
  CK_ULONG ulNewEmitentKeyLen;
  CK_ULONG ulNewEmitentKeyRetryCount;
} CK_VENDOR_RESTORE_FACTORY_DEFAULTS_PARAMS;

typedef CK_VENDOR_RESTORE_FACTORY_DEFAULTS_PARAMS * CK_VENDOR_RESTORE_FACTORY_DEFAULTS_PARAMS_PTR;



typedef struct CK_TOKEN_INFO_EXTENDED {




  CK_ULONG ulSizeofThisStructure;




  CK_ULONG ulTokenType;

  CK_ULONG ulProtocolNumber;

  CK_ULONG ulMicrocodeNumber;

  CK_ULONG ulOrderNumber;

  CK_FLAGS flags;

  CK_ULONG ulMaxAdminPinLen;
  CK_ULONG ulMinAdminPinLen;
  CK_ULONG ulMaxUserPinLen;
  CK_ULONG ulMinUserPinLen;

  CK_ULONG ulMaxAdminRetryCount;


  CK_ULONG ulAdminRetryCountLeft;

  CK_ULONG ulMaxUserRetryCount;


  CK_ULONG ulUserRetryCountLeft;

  CK_BYTE serialNumber[8];

  CK_ULONG ulTotalMemory;

  CK_ULONG ulFreeMemory;

  CK_BYTE ATR[64];

  CK_ULONG ulATRLen;

  CK_ULONG ulTokenClass;

  CK_ULONG ulBatteryVoltage;

  CK_ULONG ulBodyColor;

  CK_ULONG ulFirmwareChecksum;
} CK_TOKEN_INFO_EXTENDED;

typedef CK_TOKEN_INFO_EXTENDED * CK_TOKEN_INFO_EXTENDED_PTR;
# 432 "/usr/local/include/rtpkcs11t.h" 3
typedef CK_ULONG CK_VOLUME_ID_EXTENDED;
typedef CK_ULONG CK_ACCESS_MODE_EXTENDED;
typedef CK_ULONG CK_OWNER_EXTENDED;
# 454 "/usr/local/include/rtpkcs11t.h" 3
typedef struct CK_TOKEN_IMIT_DATA {
  CK_BYTE bMode;
  CK_BYTE pbGostSymmetricKey[32];
  CK_BYTE pbImit[8];
} CK_TOKEN_IMIT_DATA;

typedef CK_TOKEN_IMIT_DATA * CK_TOKEN_IMIT_DATA_PTR;
# 483 "/usr/local/include/rtpkcs11t.h" 3
typedef struct CK_LOCAL_PIN_INFO {
  CK_ULONG ulPinID;
  CK_ULONG ulMinSize;
  CK_ULONG ulMaxSize;
  CK_ULONG ulMaxRetryCount;
  CK_ULONG ulCurrentRetryCount;
  CK_FLAGS flags;
} CK_LOCAL_PIN_INFO;

typedef CK_LOCAL_PIN_INFO * CK_LOCAL_PIN_INFO_PTR;
# 511 "/usr/local/include/rtpkcs11t.h" 3
typedef struct CK_VOLUME_INFO_EXTENDED
{
  CK_VOLUME_ID_EXTENDED idVolume;
  CK_ULONG ulVolumeSize;
  CK_ACCESS_MODE_EXTENDED accessMode;
  CK_OWNER_EXTENDED volumeOwner;
  CK_FLAGS flags;
} CK_VOLUME_INFO_EXTENDED;

typedef struct CK_VOLUME_FORMAT_INFO_EXTENDED
{
  CK_ULONG ulVolumeSize;
  CK_ACCESS_MODE_EXTENDED accessMode;
  CK_OWNER_EXTENDED volumeOwner;
  CK_FLAGS flags;
} CK_VOLUME_FORMAT_INFO_EXTENDED;

typedef CK_VOLUME_INFO_EXTENDED * CK_VOLUME_INFO_EXTENDED_PTR;
typedef CK_VOLUME_FORMAT_INFO_EXTENDED * CK_VOLUME_FORMAT_INFO_EXTENDED_PTR;
# 545 "/usr/local/include/rtpkcs11t.h" 3
typedef struct CK_VENDOR_PIN_PARAMS {
  CK_USER_TYPE userType;
  CK_UTF8CHAR_PTR pPinValue;
  CK_ULONG ulPinLength;
} CK_VENDOR_PIN_PARAMS;

typedef CK_VENDOR_PIN_PARAMS * CK_VENDOR_PIN_PARAMS_PTR;
# 603 "/usr/local/include/rtpkcs11t.h" 3
typedef struct CK_VENDOR_BUFFER {
  CK_BYTE_PTR pData;
  CK_ULONG ulSize;
} CK_VENDOR_BUFFER;

typedef CK_VENDOR_BUFFER * CK_VENDOR_BUFFER_PTR;
typedef CK_VENDOR_BUFFER_PTR * CK_VENDOR_BUFFER_PTR_PTR;

typedef CK_ULONG CK_VENDOR_CRL_MODE;

typedef struct CK_VENDOR_X509_STORE {
  CK_VENDOR_BUFFER_PTR pTrustedCertificates;
  CK_ULONG ulTrustedCertificateCount;
  CK_VENDOR_BUFFER_PTR pCertificates;
  CK_ULONG ulCertificateCount;
  CK_VENDOR_BUFFER_PTR pCrls;
  CK_ULONG ulCrlCount;
} CK_VENDOR_X509_STORE;

typedef CK_VENDOR_X509_STORE * CK_VENDOR_X509_STORE_PTR;

typedef CK_BYTE_PTR * CK_BYTE_PTR_PTR;
# 23 "/usr/local/include/rtpkcs11.h" 2 3
# 37 "/usr/local/include/rtpkcs11.h" 3
#include "rtpkcs11f.h"
# 37 "/usr/local/include/rtpkcs11.h" 3
# 1 "/usr/local/include/rtpkcs11f.h" 1 3
# 10 "/usr/local/include/rtpkcs11f.h" 3
extern CK_RV C_EX_GetFunctionListExtended

(
  CK_FUNCTION_LIST_EXTENDED_PTR_PTR ppFunctionList

);




extern CK_RV C_EX_InitToken

(
  CK_SLOT_ID slotID,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG ulPinLen,
  CK_RUTOKEN_INIT_PARAM_PTR pInitInfo
);





extern CK_RV C_EX_GetTokenInfoExtended

(
  CK_SLOT_ID slotID,
  CK_TOKEN_INFO_EXTENDED_PTR pInfo
);






extern CK_RV C_EX_UnblockUserPIN

(
  CK_SESSION_HANDLE hSession
);







extern CK_RV C_EX_SetTokenName

(
  CK_SESSION_HANDLE hSession,
  CK_CHAR_PTR pLabel,
  CK_ULONG ulLabelLen
);
# 75 "/usr/local/include/rtpkcs11f.h" 3
extern CK_RV C_EX_SetLicense

(
  CK_SESSION_HANDLE hSession,
  CK_ULONG ulLicenseNum,
  CK_BYTE_PTR pLicense,
  CK_ULONG ulLicenseLen
);
# 96 "/usr/local/include/rtpkcs11f.h" 3
extern CK_RV C_EX_GetLicense

(
  CK_SESSION_HANDLE hSession,
  CK_ULONG ulLicenseNum,
  CK_BYTE_PTR pLicense,
  CK_ULONG_PTR pulLicenseLen
);
# 116 "/usr/local/include/rtpkcs11f.h" 3
extern CK_RV C_EX_GetCertificateInfoText

(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hCert,
  CK_CHAR_PTR *pInfo,
  CK_ULONG_PTR pulInfoLen
);







extern CK_RV C_EX_PKCS7Sign

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_OBJECT_HANDLE hCert,
  CK_BYTE_PTR *ppEnvelope,
  CK_ULONG_PTR pEnvelopeLen,
  CK_OBJECT_HANDLE hPrivKey,
  CK_OBJECT_HANDLE_PTR phCertificates,
  CK_ULONG ulCertificatesLen,
  CK_ULONG flags
);







extern CK_RV C_EX_CreateCSR

(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hPublicKey,
  CK_CHAR_PTR *dn,
  CK_ULONG dnLength,
  CK_BYTE_PTR *pCsr,
  CK_ULONG_PTR pulCsrLength,
  CK_OBJECT_HANDLE hPrivKey,
  CK_CHAR_PTR *pAttributes,
  CK_ULONG ulAttributesLength,
  CK_CHAR_PTR *pExtensions,
  CK_ULONG ulExtensionsLength
);






extern CK_RV C_EX_FreeBuffer

(
  CK_BYTE_PTR pBuffer
);
# 187 "/usr/local/include/rtpkcs11f.h" 3
extern CK_RV C_EX_GetTokenName

(
  CK_SESSION_HANDLE hSession,
  CK_CHAR_PTR pLabel,
  CK_ULONG_PTR pulLabelLen
);
# 205 "/usr/local/include/rtpkcs11f.h" 3
extern CK_RV C_EX_SetLocalPIN

(
  CK_SLOT_ID slotID,
  CK_UTF8CHAR_PTR pUserPin,
  CK_ULONG ulUserPinLen,
  CK_UTF8CHAR_PTR pNewLocalPin,
  CK_ULONG ulNewLocalPinLen,
  CK_ULONG ulLocalID
);



extern CK_RV C_EX_LoadActivationKey

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR key,
  CK_ULONG keySize
);



extern CK_RV C_EX_SetActivationPassword

(
  CK_SLOT_ID slotID,
  CK_UTF8CHAR_PTR password
);



extern CK_RV C_EX_GetVolumesInfo

(
  CK_SLOT_ID slotID,
  CK_VOLUME_INFO_EXTENDED_PTR pInfo,
  CK_ULONG_PTR pulInfoCount
);



extern CK_RV C_EX_GetDriveSize

(
  CK_SLOT_ID slotID,
  CK_ULONG_PTR pulDriveSize
);



extern CK_RV C_EX_ChangeVolumeAttributes

(
  CK_SLOT_ID slotID,
  CK_USER_TYPE userType,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG ulPinLen,
  CK_VOLUME_ID_EXTENDED idVolume,
  CK_ACCESS_MODE_EXTENDED newAccessMode,
  CK_BBOOL bPermanent
);



extern CK_RV C_EX_FormatDrive

(
  CK_SLOT_ID slotID,
  CK_USER_TYPE userType,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG ulPinLen,
  CK_VOLUME_FORMAT_INFO_EXTENDED_PTR pInitParams,
  CK_ULONG ulInitParamsCount
);



extern CK_RV C_EX_TokenManage

(
  CK_SESSION_HANDLE hSession,
  CK_ULONG ulMode,
  CK_VOID_PTR pValue
);



extern CK_RV C_EX_GenerateActivationPassword

(
  CK_SESSION_HANDLE hSession,
  CK_ULONG ulPasswordNumber,
  CK_UTF8CHAR_PTR pPassword,
  CK_ULONG_PTR pulPasswordSize,
  CK_ULONG ulPasswordCharacterSet
);



extern CK_RV C_EX_GetJournal

(
  CK_SLOT_ID slotID,
  CK_BYTE_PTR pJournal,
  CK_ULONG_PTR pulJournalSize
);



extern CK_RV C_EX_SignInvisibleInit

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
);



extern CK_RV C_EX_SignInvisible

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen
);



extern CK_RV C_EX_SlotManage

(
  CK_SLOT_ID slotID,
  CK_ULONG ulMode,
  CK_VOID_PTR pValue
);



extern CK_RV C_EX_WrapKey

(
 CK_SESSION_HANDLE hSession,
 CK_MECHANISM_PTR pGenerationMechanism,
 CK_ATTRIBUTE_PTR pKeyTemplate,
 CK_ULONG ulKeyAttributeCount,
 CK_MECHANISM_PTR pDerivationMechanism,
 CK_OBJECT_HANDLE hBaseKey,
 CK_MECHANISM_PTR pWrappingMechanism,
 CK_BYTE_PTR pWrappedKey,
 CK_ULONG_PTR pulWrappedKeyLen,
 CK_OBJECT_HANDLE_PTR phKey
);



extern CK_RV C_EX_UnwrapKey

(
 CK_SESSION_HANDLE hSession,
 CK_MECHANISM_PTR pDerivationMechanism,
 CK_OBJECT_HANDLE hBaseKey,
 CK_MECHANISM_PTR pUnwrappingMechanism,
 CK_BYTE_PTR pWrappedKey,
 CK_ULONG ulWrappedKeyLen,
 CK_ATTRIBUTE_PTR pKeyTemplate,
 CK_ULONG ulKeyAttributeCount,
 CK_OBJECT_HANDLE_PTR phKey
);



extern CK_RV C_EX_PKCS7VerifyInit

(
 CK_SESSION_HANDLE hSession,
 CK_BYTE_PTR pCms,
 CK_ULONG ulCmsSize,
 CK_VENDOR_X509_STORE_PTR pStore,
 CK_VENDOR_CRL_MODE ckMode,
 CK_FLAGS flags
);



extern CK_RV C_EX_PKCS7Verify

(
 CK_SESSION_HANDLE hSession,
 CK_BYTE_PTR_PTR ppData,
 CK_ULONG_PTR pulDataSize,
 CK_VENDOR_BUFFER_PTR_PTR ppSignerCertificates,
 CK_ULONG_PTR pulSignerCertificatesCount
);



extern CK_RV C_EX_PKCS7VerifyUpdate

(
 CK_SESSION_HANDLE hSession,
 CK_BYTE_PTR pData,
 CK_ULONG ulDataSize
);



extern CK_RV C_EX_PKCS7VerifyFinal

(
 CK_SESSION_HANDLE hSession,
 CK_VENDOR_BUFFER_PTR_PTR ppSignerCertificates,
 CK_ULONG_PTR pulSignerCertificatesCount
);
# 38 "/usr/local/include/rtpkcs11.h" 2 3
# 56 "/usr/local/include/rtpkcs11.h" 3
#include "rtpkcs11f.h"
# 56 "/usr/local/include/rtpkcs11.h" 3
# 1 "/usr/local/include/rtpkcs11f.h" 1 3
# 10 "/usr/local/include/rtpkcs11f.h" 3
typedef CK_RV ( * CK_C_EX_GetFunctionListExtended)

(
  CK_FUNCTION_LIST_EXTENDED_PTR_PTR ppFunctionList

);




typedef CK_RV ( * CK_C_EX_InitToken)

(
  CK_SLOT_ID slotID,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG ulPinLen,
  CK_RUTOKEN_INIT_PARAM_PTR pInitInfo
);





typedef CK_RV ( * CK_C_EX_GetTokenInfoExtended)

(
  CK_SLOT_ID slotID,
  CK_TOKEN_INFO_EXTENDED_PTR pInfo
);






typedef CK_RV ( * CK_C_EX_UnblockUserPIN)

(
  CK_SESSION_HANDLE hSession
);







typedef CK_RV ( * CK_C_EX_SetTokenName)

(
  CK_SESSION_HANDLE hSession,
  CK_CHAR_PTR pLabel,
  CK_ULONG ulLabelLen
);
# 75 "/usr/local/include/rtpkcs11f.h" 3
typedef CK_RV ( * CK_C_EX_SetLicense)

(
  CK_SESSION_HANDLE hSession,
  CK_ULONG ulLicenseNum,
  CK_BYTE_PTR pLicense,
  CK_ULONG ulLicenseLen
);
# 96 "/usr/local/include/rtpkcs11f.h" 3
typedef CK_RV ( * CK_C_EX_GetLicense)

(
  CK_SESSION_HANDLE hSession,
  CK_ULONG ulLicenseNum,
  CK_BYTE_PTR pLicense,
  CK_ULONG_PTR pulLicenseLen
);
# 116 "/usr/local/include/rtpkcs11f.h" 3
typedef CK_RV ( * CK_C_EX_GetCertificateInfoText)

(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hCert,
  CK_CHAR_PTR *pInfo,
  CK_ULONG_PTR pulInfoLen
);







typedef CK_RV ( * CK_C_EX_PKCS7Sign)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_OBJECT_HANDLE hCert,
  CK_BYTE_PTR *ppEnvelope,
  CK_ULONG_PTR pEnvelopeLen,
  CK_OBJECT_HANDLE hPrivKey,
  CK_OBJECT_HANDLE_PTR phCertificates,
  CK_ULONG ulCertificatesLen,
  CK_ULONG flags
);







typedef CK_RV ( * CK_C_EX_CreateCSR)

(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hPublicKey,
  CK_CHAR_PTR *dn,
  CK_ULONG dnLength,
  CK_BYTE_PTR *pCsr,
  CK_ULONG_PTR pulCsrLength,
  CK_OBJECT_HANDLE hPrivKey,
  CK_CHAR_PTR *pAttributes,
  CK_ULONG ulAttributesLength,
  CK_CHAR_PTR *pExtensions,
  CK_ULONG ulExtensionsLength
);






typedef CK_RV ( * CK_C_EX_FreeBuffer)

(
  CK_BYTE_PTR pBuffer
);
# 187 "/usr/local/include/rtpkcs11f.h" 3
typedef CK_RV ( * CK_C_EX_GetTokenName)

(
  CK_SESSION_HANDLE hSession,
  CK_CHAR_PTR pLabel,
  CK_ULONG_PTR pulLabelLen
);
# 205 "/usr/local/include/rtpkcs11f.h" 3
typedef CK_RV ( * CK_C_EX_SetLocalPIN)

(
  CK_SLOT_ID slotID,
  CK_UTF8CHAR_PTR pUserPin,
  CK_ULONG ulUserPinLen,
  CK_UTF8CHAR_PTR pNewLocalPin,
  CK_ULONG ulNewLocalPinLen,
  CK_ULONG ulLocalID
);



typedef CK_RV ( * CK_C_EX_LoadActivationKey)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR key,
  CK_ULONG keySize
);



typedef CK_RV ( * CK_C_EX_SetActivationPassword)

(
  CK_SLOT_ID slotID,
  CK_UTF8CHAR_PTR password
);



typedef CK_RV ( * CK_C_EX_GetVolumesInfo)

(
  CK_SLOT_ID slotID,
  CK_VOLUME_INFO_EXTENDED_PTR pInfo,
  CK_ULONG_PTR pulInfoCount
);



typedef CK_RV ( * CK_C_EX_GetDriveSize)

(
  CK_SLOT_ID slotID,
  CK_ULONG_PTR pulDriveSize
);



typedef CK_RV ( * CK_C_EX_ChangeVolumeAttributes)

(
  CK_SLOT_ID slotID,
  CK_USER_TYPE userType,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG ulPinLen,
  CK_VOLUME_ID_EXTENDED idVolume,
  CK_ACCESS_MODE_EXTENDED newAccessMode,
  CK_BBOOL bPermanent
);



typedef CK_RV ( * CK_C_EX_FormatDrive)

(
  CK_SLOT_ID slotID,
  CK_USER_TYPE userType,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG ulPinLen,
  CK_VOLUME_FORMAT_INFO_EXTENDED_PTR pInitParams,
  CK_ULONG ulInitParamsCount
);



typedef CK_RV ( * CK_C_EX_TokenManage)

(
  CK_SESSION_HANDLE hSession,
  CK_ULONG ulMode,
  CK_VOID_PTR pValue
);



typedef CK_RV ( * CK_C_EX_GenerateActivationPassword)

(
  CK_SESSION_HANDLE hSession,
  CK_ULONG ulPasswordNumber,
  CK_UTF8CHAR_PTR pPassword,
  CK_ULONG_PTR pulPasswordSize,
  CK_ULONG ulPasswordCharacterSet
);



typedef CK_RV ( * CK_C_EX_GetJournal)

(
  CK_SLOT_ID slotID,
  CK_BYTE_PTR pJournal,
  CK_ULONG_PTR pulJournalSize
);



typedef CK_RV ( * CK_C_EX_SignInvisibleInit)

(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR pMechanism,
  CK_OBJECT_HANDLE hKey
);



typedef CK_RV ( * CK_C_EX_SignInvisible)

(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR pData,
  CK_ULONG ulDataLen,
  CK_BYTE_PTR pSignature,
  CK_ULONG_PTR pulSignatureLen
);



typedef CK_RV ( * CK_C_EX_SlotManage)

(
  CK_SLOT_ID slotID,
  CK_ULONG ulMode,
  CK_VOID_PTR pValue
);



typedef CK_RV ( * CK_C_EX_WrapKey)

(
 CK_SESSION_HANDLE hSession,
 CK_MECHANISM_PTR pGenerationMechanism,
 CK_ATTRIBUTE_PTR pKeyTemplate,
 CK_ULONG ulKeyAttributeCount,
 CK_MECHANISM_PTR pDerivationMechanism,
 CK_OBJECT_HANDLE hBaseKey,
 CK_MECHANISM_PTR pWrappingMechanism,
 CK_BYTE_PTR pWrappedKey,
 CK_ULONG_PTR pulWrappedKeyLen,
 CK_OBJECT_HANDLE_PTR phKey
);



typedef CK_RV ( * CK_C_EX_UnwrapKey)

(
 CK_SESSION_HANDLE hSession,
 CK_MECHANISM_PTR pDerivationMechanism,
 CK_OBJECT_HANDLE hBaseKey,
 CK_MECHANISM_PTR pUnwrappingMechanism,
 CK_BYTE_PTR pWrappedKey,
 CK_ULONG ulWrappedKeyLen,
 CK_ATTRIBUTE_PTR pKeyTemplate,
 CK_ULONG ulKeyAttributeCount,
 CK_OBJECT_HANDLE_PTR phKey
);



typedef CK_RV ( * CK_C_EX_PKCS7VerifyInit)

(
 CK_SESSION_HANDLE hSession,
 CK_BYTE_PTR pCms,
 CK_ULONG ulCmsSize,
 CK_VENDOR_X509_STORE_PTR pStore,
 CK_VENDOR_CRL_MODE ckMode,
 CK_FLAGS flags
);



typedef CK_RV ( * CK_C_EX_PKCS7Verify)

(
 CK_SESSION_HANDLE hSession,
 CK_BYTE_PTR_PTR ppData,
 CK_ULONG_PTR pulDataSize,
 CK_VENDOR_BUFFER_PTR_PTR ppSignerCertificates,
 CK_ULONG_PTR pulSignerCertificatesCount
);



typedef CK_RV ( * CK_C_EX_PKCS7VerifyUpdate)

(
 CK_SESSION_HANDLE hSession,
 CK_BYTE_PTR pData,
 CK_ULONG ulDataSize
);



typedef CK_RV ( * CK_C_EX_PKCS7VerifyFinal)

(
 CK_SESSION_HANDLE hSession,
 CK_VENDOR_BUFFER_PTR_PTR ppSignerCertificates,
 CK_ULONG_PTR pulSignerCertificatesCount
);
# 57 "/usr/local/include/rtpkcs11.h" 2 3
# 75 "/usr/local/include/rtpkcs11.h" 3
struct CK_FUNCTION_LIST_EXTENDED {

  CK_VERSION version;





#include "rtpkcs11f.h"
# 83 "/usr/local/include/rtpkcs11.h" 3
# 1 "/usr/local/include/rtpkcs11f.h" 1 3
# 10 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_GetFunctionListExtended C_EX_GetFunctionListExtended;
# 20 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_InitToken C_EX_InitToken;
# 33 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_GetTokenInfoExtended C_EX_GetTokenInfoExtended;
# 45 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_UnblockUserPIN C_EX_UnblockUserPIN;
# 57 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_SetTokenName C_EX_SetTokenName;
# 75 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_SetLicense C_EX_SetLicense;
# 96 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_GetLicense C_EX_GetLicense;
# 116 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_GetCertificateInfoText C_EX_GetCertificateInfoText;
# 131 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_PKCS7Sign C_EX_PKCS7Sign;
# 152 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_CreateCSR C_EX_CreateCSR;
# 173 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_FreeBuffer C_EX_FreeBuffer;
# 187 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_GetTokenName C_EX_GetTokenName;
# 205 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_SetLocalPIN C_EX_SetLocalPIN;
# 218 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_LoadActivationKey C_EX_LoadActivationKey;
# 228 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_SetActivationPassword C_EX_SetActivationPassword;
# 237 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_GetVolumesInfo C_EX_GetVolumesInfo;
# 247 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_GetDriveSize C_EX_GetDriveSize;
# 256 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_ChangeVolumeAttributes C_EX_ChangeVolumeAttributes;
# 270 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_FormatDrive C_EX_FormatDrive;
# 283 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_TokenManage C_EX_TokenManage;
# 293 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_GenerateActivationPassword C_EX_GenerateActivationPassword;
# 305 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_GetJournal C_EX_GetJournal;
# 315 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_SignInvisibleInit C_EX_SignInvisibleInit;
# 325 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_SignInvisible C_EX_SignInvisible;
# 337 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_SlotManage C_EX_SlotManage;
# 347 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_WrapKey C_EX_WrapKey;
# 364 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_UnwrapKey C_EX_UnwrapKey;
# 380 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_PKCS7VerifyInit C_EX_PKCS7VerifyInit;
# 393 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_PKCS7Verify C_EX_PKCS7Verify;
# 405 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_PKCS7VerifyUpdate C_EX_PKCS7VerifyUpdate;
# 415 "/usr/local/include/rtpkcs11f.h" 3
CK_C_EX_PKCS7VerifyFinal C_EX_PKCS7VerifyFinal;
# 84 "/usr/local/include/rtpkcs11.h" 2 3

};
# 35 "/usr/local/include/Common.h" 2 3
#include <win2nix.h>
# 35 "/usr/local/include/Common.h" 3
# 1 "/usr/local/include/win2nix.h" 1 3
# 13 "/usr/local/include/win2nix.h" 3
#include <stddef.h>
# 13 "/usr/local/include/win2nix.h" 3
# 1 "/usr/lib/gcc/x86_64-redhat-linux/9/include/stddef.h" 1 3 4
# 143 "/usr/lib/gcc/x86_64-redhat-linux/9/include/stddef.h" 3 4
typedef long int ptrdiff_t;
# 209 "/usr/lib/gcc/x86_64-redhat-linux/9/include/stddef.h" 3 4
typedef long unsigned int size_t;
# 321 "/usr/lib/gcc/x86_64-redhat-linux/9/include/stddef.h" 3 4
typedef int wchar_t;
# 415 "/usr/lib/gcc/x86_64-redhat-linux/9/include/stddef.h" 3 4
typedef struct {
  long long __max_align_ll __attribute__((__aligned__(__alignof__(long long))));
  long double __max_align_ld __attribute__((__aligned__(__alignof__(long double))));
# 426 "/usr/lib/gcc/x86_64-redhat-linux/9/include/stddef.h" 3 4
} max_align_t;
# 14 "/usr/local/include/win2nix.h" 2 3
#include <stdint.h>
# 14 "/usr/local/include/win2nix.h" 3
# 1 "/usr/lib/gcc/x86_64-redhat-linux/9/include/stdint.h" 1 3 4
# 9 "/usr/lib/gcc/x86_64-redhat-linux/9/include/stdint.h" 3 4
#include_next <stdint.h>
# 9 "/usr/lib/gcc/x86_64-redhat-linux/9/include/stdint.h" 3 4
# 1 "/usr/include/stdint.h" 1 3 4
# 26 "/usr/include/stdint.h" 3 4
#include <bits/libc-header-start.h>
# 26 "/usr/include/stdint.h" 3 4
# 1 "/usr/include/bits/libc-header-start.h" 1 3 4
# 33 "/usr/include/bits/libc-header-start.h" 3 4
#include <features.h>
# 33 "/usr/include/bits/libc-header-start.h" 3 4
# 1 "/usr/include/features.h" 1 3 4
# 428 "/usr/include/features.h" 3 4
#include <stdc-predef.h>
# 450 "/usr/include/features.h" 3 4
#include <sys/cdefs.h>
# 450 "/usr/include/features.h" 3 4
# 1 "/usr/include/sys/cdefs.h" 1 3 4
# 452 "/usr/include/sys/cdefs.h" 3 4
#include <bits/wordsize.h>
# 452 "/usr/include/sys/cdefs.h" 3 4
# 1 "/usr/include/bits/wordsize.h" 1 3 4
# 453 "/usr/include/sys/cdefs.h" 2 3 4
#include <bits/long-double.h>
# 453 "/usr/include/sys/cdefs.h" 3 4
# 1 "/usr/include/bits/long-double.h" 1 3 4
# 454 "/usr/include/sys/cdefs.h" 2 3 4
# 451 "/usr/include/features.h" 2 3 4
# 474 "/usr/include/features.h" 3 4
#include <gnu/stubs.h>
# 474 "/usr/include/features.h" 3 4
# 1 "/usr/include/gnu/stubs.h" 1 3 4
# 10 "/usr/include/gnu/stubs.h" 3 4
#include <gnu/stubs-64.h>
# 10 "/usr/include/gnu/stubs.h" 3 4
# 1 "/usr/include/gnu/stubs-64.h" 1 3 4
# 11 "/usr/include/gnu/stubs.h" 2 3 4
# 475 "/usr/include/features.h" 2 3 4
# 34 "/usr/include/bits/libc-header-start.h" 2 3 4
# 27 "/usr/include/stdint.h" 2 3 4
#include <bits/types.h>
# 27 "/usr/include/stdint.h" 3 4
# 1 "/usr/include/bits/types.h" 1 3 4
# 26 "/usr/include/bits/types.h" 3 4
#include <features.h>
#include <bits/wordsize.h>
# 27 "/usr/include/bits/types.h" 3 4
# 1 "/usr/include/bits/wordsize.h" 1 3 4
# 28 "/usr/include/bits/types.h" 2 3 4
#include <bits/timesize.h>
# 28 "/usr/include/bits/types.h" 3 4
# 1 "/usr/include/bits/timesize.h" 1 3 4
# 29 "/usr/include/bits/types.h" 2 3 4


typedef unsigned char __u_char;
typedef unsigned short int __u_short;
typedef unsigned int __u_int;
typedef unsigned long int __u_long;


typedef signed char __int8_t;
typedef unsigned char __uint8_t;
typedef signed short int __int16_t;
typedef unsigned short int __uint16_t;
typedef signed int __int32_t;
typedef unsigned int __uint32_t;

typedef signed long int __int64_t;
typedef unsigned long int __uint64_t;






typedef __int8_t __int_least8_t;
typedef __uint8_t __uint_least8_t;
typedef __int16_t __int_least16_t;
typedef __uint16_t __uint_least16_t;
typedef __int32_t __int_least32_t;
typedef __uint32_t __uint_least32_t;
typedef __int64_t __int_least64_t;
typedef __uint64_t __uint_least64_t;



typedef long int __quad_t;
typedef unsigned long int __u_quad_t;







typedef long int __intmax_t;
typedef unsigned long int __uintmax_t;
# 141 "/usr/include/bits/types.h" 3 4
#include <bits/typesizes.h>
# 141 "/usr/include/bits/types.h" 3 4
# 1 "/usr/include/bits/typesizes.h" 1 3 4
# 142 "/usr/include/bits/types.h" 2 3 4
#include <bits/time64.h>
# 142 "/usr/include/bits/types.h" 3 4
# 1 "/usr/include/bits/time64.h" 1 3 4
# 143 "/usr/include/bits/types.h" 2 3 4


typedef unsigned long int __dev_t;
typedef unsigned int __uid_t;
typedef unsigned int __gid_t;
typedef unsigned long int __ino_t;
typedef unsigned long int __ino64_t;
typedef unsigned int __mode_t;
typedef unsigned long int __nlink_t;
typedef long int __off_t;
typedef long int __off64_t;
typedef int __pid_t;
typedef struct { int __val[2]; } __fsid_t;
typedef long int __clock_t;
typedef unsigned long int __rlim_t;
typedef unsigned long int __rlim64_t;
typedef unsigned int __id_t;
typedef long int __time_t;
typedef unsigned int __useconds_t;
typedef long int __suseconds_t;

typedef int __daddr_t;
typedef int __key_t;


typedef int __clockid_t;


typedef void * __timer_t;


typedef long int __blksize_t;




typedef long int __blkcnt_t;
typedef long int __blkcnt64_t;


typedef unsigned long int __fsblkcnt_t;
typedef unsigned long int __fsblkcnt64_t;


typedef unsigned long int __fsfilcnt_t;
typedef unsigned long int __fsfilcnt64_t;


typedef long int __fsword_t;

typedef long int __ssize_t;


typedef long int __syscall_slong_t;

typedef unsigned long int __syscall_ulong_t;



typedef __off64_t __loff_t;
typedef char *__caddr_t;


typedef long int __intptr_t;


typedef unsigned int __socklen_t;




typedef int __sig_atomic_t;
# 28 "/usr/include/stdint.h" 2 3 4
#include <bits/wchar.h>
# 28 "/usr/include/stdint.h" 3 4
# 1 "/usr/include/bits/wchar.h" 1 3 4
# 29 "/usr/include/stdint.h" 2 3 4
#include <bits/wordsize.h>
# 29 "/usr/include/stdint.h" 3 4
# 1 "/usr/include/bits/wordsize.h" 1 3 4
# 30 "/usr/include/stdint.h" 2 3 4




#include <bits/stdint-intn.h>
# 34 "/usr/include/stdint.h" 3 4
# 1 "/usr/include/bits/stdint-intn.h" 1 3 4
# 22 "/usr/include/bits/stdint-intn.h" 3 4
#include <bits/types.h>

typedef __int8_t int8_t;
typedef __int16_t int16_t;
typedef __int32_t int32_t;
typedef __int64_t int64_t;
# 35 "/usr/include/stdint.h" 2 3 4


#include <bits/stdint-uintn.h>
# 37 "/usr/include/stdint.h" 3 4
# 1 "/usr/include/bits/stdint-uintn.h" 1 3 4
# 22 "/usr/include/bits/stdint-uintn.h" 3 4
#include <bits/types.h>

typedef __uint8_t uint8_t;
typedef __uint16_t uint16_t;
typedef __uint32_t uint32_t;
typedef __uint64_t uint64_t;
# 38 "/usr/include/stdint.h" 2 3 4





typedef __int_least8_t int_least8_t;
typedef __int_least16_t int_least16_t;
typedef __int_least32_t int_least32_t;
typedef __int_least64_t int_least64_t;


typedef __uint_least8_t uint_least8_t;
typedef __uint_least16_t uint_least16_t;
typedef __uint_least32_t uint_least32_t;
typedef __uint_least64_t uint_least64_t;





typedef signed char int_fast8_t;

typedef long int int_fast16_t;
typedef long int int_fast32_t;
typedef long int int_fast64_t;
# 71 "/usr/include/stdint.h" 3 4
typedef unsigned char uint_fast8_t;

typedef unsigned long int uint_fast16_t;
typedef unsigned long int uint_fast32_t;
typedef unsigned long int uint_fast64_t;
# 87 "/usr/include/stdint.h" 3 4
typedef long int intptr_t;


typedef unsigned long int uintptr_t;
# 101 "/usr/include/stdint.h" 3 4
typedef __intmax_t intmax_t;
typedef __uintmax_t uintmax_t;
# 10 "/usr/lib/gcc/x86_64-redhat-linux/9/include/stdint.h" 2 3 4
# 15 "/usr/local/include/win2nix.h" 2 3
#include <stdio.h>
# 15 "/usr/local/include/win2nix.h" 3
# 1 "/usr/include/stdio.h" 1 3 4
# 27 "/usr/include/stdio.h" 3 4
#include <bits/libc-header-start.h>
# 27 "/usr/include/stdio.h" 3 4
# 1 "/usr/include/bits/libc-header-start.h" 1 3 4
# 33 "/usr/include/bits/libc-header-start.h" 3 4
#include <features.h>
# 28 "/usr/include/stdio.h" 2 3 4





#include <stddef.h>
# 33 "/usr/include/stdio.h" 3 4
# 1 "/usr/lib/gcc/x86_64-redhat-linux/9/include/stddef.h" 1 3 4
# 34 "/usr/include/stdio.h" 2 3 4


#include <stdarg.h>
# 36 "/usr/include/stdio.h" 3 4
# 1 "/usr/lib/gcc/x86_64-redhat-linux/9/include/stdarg.h" 1 3 4
# 40 "/usr/lib/gcc/x86_64-redhat-linux/9/include/stdarg.h" 3 4
typedef __builtin_va_list __gnuc_va_list;
# 37 "/usr/include/stdio.h" 2 3 4

#include <bits/types.h>
#include <bits/types/__fpos_t.h>
# 39 "/usr/include/stdio.h" 3 4
# 1 "/usr/include/bits/types/__fpos_t.h" 1 3 4



#include <bits/types.h>
#include <bits/types/__mbstate_t.h>
# 5 "/usr/include/bits/types/__fpos_t.h" 3 4
# 1 "/usr/include/bits/types/__mbstate_t.h" 1 3 4
# 13 "/usr/include/bits/types/__mbstate_t.h" 3 4
typedef struct
{
  int __count;
  union
  {
    unsigned int __wch;
    char __wchb[4];
  } __value;
} __mbstate_t;
# 6 "/usr/include/bits/types/__fpos_t.h" 2 3 4




typedef struct _G_fpos_t
{
  __off_t __pos;
  __mbstate_t __state;
} __fpos_t;
# 40 "/usr/include/stdio.h" 2 3 4
#include <bits/types/__fpos64_t.h>
# 40 "/usr/include/stdio.h" 3 4
# 1 "/usr/include/bits/types/__fpos64_t.h" 1 3 4



#include <bits/types.h>
#include <bits/types/__mbstate_t.h>




typedef struct _G_fpos64_t
{
  __off64_t __pos;
  __mbstate_t __state;
} __fpos64_t;
# 41 "/usr/include/stdio.h" 2 3 4
#include <bits/types/__FILE.h>
# 41 "/usr/include/stdio.h" 3 4
# 1 "/usr/include/bits/types/__FILE.h" 1 3 4



struct _IO_FILE;
typedef struct _IO_FILE __FILE;
# 42 "/usr/include/stdio.h" 2 3 4
#include <bits/types/FILE.h>
# 42 "/usr/include/stdio.h" 3 4
# 1 "/usr/include/bits/types/FILE.h" 1 3 4



struct _IO_FILE;


typedef struct _IO_FILE FILE;
# 43 "/usr/include/stdio.h" 2 3 4
#include <bits/types/struct_FILE.h>
# 43 "/usr/include/stdio.h" 3 4
# 1 "/usr/include/bits/types/struct_FILE.h" 1 3 4
# 33 "/usr/include/bits/types/struct_FILE.h" 3 4
#include <bits/types.h>

struct _IO_FILE;
struct _IO_marker;
struct _IO_codecvt;
struct _IO_wide_data;




typedef void _IO_lock_t;





struct _IO_FILE
{
  int _flags;


  char *_IO_read_ptr;
  char *_IO_read_end;
  char *_IO_read_base;
  char *_IO_write_base;
  char *_IO_write_ptr;
  char *_IO_write_end;
  char *_IO_buf_base;
  char *_IO_buf_end;


  char *_IO_save_base;
  char *_IO_backup_base;
  char *_IO_save_end;

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  int _flags2;
  __off_t _old_offset;


  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;







  __off64_t _offset;

  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;

  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
# 44 "/usr/include/stdio.h" 2 3 4
# 52 "/usr/include/stdio.h" 3 4
typedef __gnuc_va_list va_list;
# 63 "/usr/include/stdio.h" 3 4
typedef __off_t off_t;
# 77 "/usr/include/stdio.h" 3 4
typedef __ssize_t ssize_t;






typedef __fpos_t fpos_t;
# 133 "/usr/include/stdio.h" 3 4
#include <bits/stdio_lim.h>
# 133 "/usr/include/stdio.h" 3 4
# 1 "/usr/include/bits/stdio_lim.h" 1 3 4
# 134 "/usr/include/stdio.h" 2 3 4



extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;






extern int remove (const char *__filename) __attribute__ ((__nothrow__ , __leaf__));

extern int rename (const char *__old, const char *__new) __attribute__ ((__nothrow__ , __leaf__));



extern int renameat (int __oldfd, const char *__old, int __newfd,
       const char *__new) __attribute__ ((__nothrow__ , __leaf__));
# 173 "/usr/include/stdio.h" 3 4
extern FILE *tmpfile (void) ;
# 187 "/usr/include/stdio.h" 3 4
extern char *tmpnam (char *__s) __attribute__ ((__nothrow__ , __leaf__)) ;




extern char *tmpnam_r (char *__s) __attribute__ ((__nothrow__ , __leaf__)) ;
# 204 "/usr/include/stdio.h" 3 4
extern char *tempnam (const char *__dir, const char *__pfx)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__malloc__)) ;







extern int fclose (FILE *__stream);




extern int fflush (FILE *__stream);
# 227 "/usr/include/stdio.h" 3 4
extern int fflush_unlocked (FILE *__stream);
# 246 "/usr/include/stdio.h" 3 4
extern FILE *fopen (const char *__restrict __filename,
      const char *__restrict __modes) ;




extern FILE *freopen (const char *__restrict __filename,
        const char *__restrict __modes,
        FILE *__restrict __stream) ;
# 279 "/usr/include/stdio.h" 3 4
extern FILE *fdopen (int __fd, const char *__modes) __attribute__ ((__nothrow__ , __leaf__)) ;
# 292 "/usr/include/stdio.h" 3 4
extern FILE *fmemopen (void *__s, size_t __len, const char *__modes)
  __attribute__ ((__nothrow__ , __leaf__)) ;




extern FILE *open_memstream (char **__bufloc, size_t *__sizeloc) __attribute__ ((__nothrow__ , __leaf__)) ;





extern void setbuf (FILE *__restrict __stream, char *__restrict __buf) __attribute__ ((__nothrow__ , __leaf__));



extern int setvbuf (FILE *__restrict __stream, char *__restrict __buf,
      int __modes, size_t __n) __attribute__ ((__nothrow__ , __leaf__));




extern void setbuffer (FILE *__restrict __stream, char *__restrict __buf,
         size_t __size) __attribute__ ((__nothrow__ , __leaf__));


extern void setlinebuf (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__));







extern int fprintf (FILE *__restrict __stream,
      const char *__restrict __format, ...);




extern int printf (const char *__restrict __format, ...);

extern int sprintf (char *__restrict __s,
      const char *__restrict __format, ...) __attribute__ ((__nothrow__));





extern int vfprintf (FILE *__restrict __s, const char *__restrict __format,
       __gnuc_va_list __arg);




extern int vprintf (const char *__restrict __format, __gnuc_va_list __arg);

extern int vsprintf (char *__restrict __s, const char *__restrict __format,
       __gnuc_va_list __arg) __attribute__ ((__nothrow__));



extern int snprintf (char *__restrict __s, size_t __maxlen,
       const char *__restrict __format, ...)
     __attribute__ ((__nothrow__)) __attribute__ ((__format__ (__printf__, 3, 4)));

extern int vsnprintf (char *__restrict __s, size_t __maxlen,
        const char *__restrict __format, __gnuc_va_list __arg)
     __attribute__ ((__nothrow__)) __attribute__ ((__format__ (__printf__, 3, 0)));
# 379 "/usr/include/stdio.h" 3 4
extern int vdprintf (int __fd, const char *__restrict __fmt,
       __gnuc_va_list __arg)
     __attribute__ ((__format__ (__printf__, 2, 0)));
extern int dprintf (int __fd, const char *__restrict __fmt, ...)
     __attribute__ ((__format__ (__printf__, 2, 3)));







extern int fscanf (FILE *__restrict __stream,
     const char *__restrict __format, ...) ;




extern int scanf (const char *__restrict __format, ...) ;

extern int sscanf (const char *__restrict __s,
     const char *__restrict __format, ...) __attribute__ ((__nothrow__ , __leaf__));






extern int fscanf (FILE *__restrict __stream, const char *__restrict __format, ...) __asm__ ("" "__isoc99_fscanf")

                               ;
extern int scanf (const char *__restrict __format, ...) __asm__ ("" "__isoc99_scanf")
                              ;
extern int sscanf (const char *__restrict __s, const char *__restrict __format, ...) __asm__ ("" "__isoc99_sscanf") __attribute__ ((__nothrow__ , __leaf__))

                      ;
# 432 "/usr/include/stdio.h" 3 4
extern int vfscanf (FILE *__restrict __s, const char *__restrict __format,
      __gnuc_va_list __arg)
     __attribute__ ((__format__ (__scanf__, 2, 0))) ;





extern int vscanf (const char *__restrict __format, __gnuc_va_list __arg)
     __attribute__ ((__format__ (__scanf__, 1, 0))) ;


extern int vsscanf (const char *__restrict __s,
      const char *__restrict __format, __gnuc_va_list __arg)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__format__ (__scanf__, 2, 0)));




extern int vfscanf (FILE *__restrict __s, const char *__restrict __format, __gnuc_va_list __arg) __asm__ ("" "__isoc99_vfscanf")



     __attribute__ ((__format__ (__scanf__, 2, 0))) ;
extern int vscanf (const char *__restrict __format, __gnuc_va_list __arg) __asm__ ("" "__isoc99_vscanf")

     __attribute__ ((__format__ (__scanf__, 1, 0))) ;
extern int vsscanf (const char *__restrict __s, const char *__restrict __format, __gnuc_va_list __arg) __asm__ ("" "__isoc99_vsscanf") __attribute__ ((__nothrow__ , __leaf__))



     __attribute__ ((__format__ (__scanf__, 2, 0)));
# 485 "/usr/include/stdio.h" 3 4
extern int fgetc (FILE *__stream);
extern int getc (FILE *__stream);





extern int getchar (void);






extern int getc_unlocked (FILE *__stream);
extern int getchar_unlocked (void);
# 510 "/usr/include/stdio.h" 3 4
extern int fgetc_unlocked (FILE *__stream);
# 521 "/usr/include/stdio.h" 3 4
extern int fputc (int __c, FILE *__stream);
extern int putc (int __c, FILE *__stream);





extern int putchar (int __c);
# 537 "/usr/include/stdio.h" 3 4
extern int fputc_unlocked (int __c, FILE *__stream);







extern int putc_unlocked (int __c, FILE *__stream);
extern int putchar_unlocked (int __c);






extern int getw (FILE *__stream);


extern int putw (int __w, FILE *__stream);







extern char *fgets (char *__restrict __s, int __n, FILE *__restrict __stream)
     ;
# 603 "/usr/include/stdio.h" 3 4
extern __ssize_t __getdelim (char **__restrict __lineptr,
                             size_t *__restrict __n, int __delimiter,
                             FILE *__restrict __stream) ;
extern __ssize_t getdelim (char **__restrict __lineptr,
                           size_t *__restrict __n, int __delimiter,
                           FILE *__restrict __stream) ;







extern __ssize_t getline (char **__restrict __lineptr,
                          size_t *__restrict __n,
                          FILE *__restrict __stream) ;







extern int fputs (const char *__restrict __s, FILE *__restrict __stream);





extern int puts (const char *__s);






extern int ungetc (int __c, FILE *__stream);






extern size_t fread (void *__restrict __ptr, size_t __size,
       size_t __n, FILE *__restrict __stream) ;




extern size_t fwrite (const void *__restrict __ptr, size_t __size,
        size_t __n, FILE *__restrict __s);
# 673 "/usr/include/stdio.h" 3 4
extern size_t fread_unlocked (void *__restrict __ptr, size_t __size,
         size_t __n, FILE *__restrict __stream) ;
extern size_t fwrite_unlocked (const void *__restrict __ptr, size_t __size,
          size_t __n, FILE *__restrict __stream);







extern int fseek (FILE *__stream, long int __off, int __whence);




extern long int ftell (FILE *__stream) ;




extern void rewind (FILE *__stream);
# 707 "/usr/include/stdio.h" 3 4
extern int fseeko (FILE *__stream, __off_t __off, int __whence);




extern __off_t ftello (FILE *__stream) ;
# 731 "/usr/include/stdio.h" 3 4
extern int fgetpos (FILE *__restrict __stream, fpos_t *__restrict __pos);




extern int fsetpos (FILE *__stream, const fpos_t *__pos);
# 757 "/usr/include/stdio.h" 3 4
extern void clearerr (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__));

extern int feof (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;

extern int ferror (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;



extern void clearerr_unlocked (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__));
extern int feof_unlocked (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;
extern int ferror_unlocked (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;







extern void perror (const char *__s);





#include <bits/sys_errlist.h>
# 781 "/usr/include/stdio.h" 3 4
# 1 "/usr/include/bits/sys_errlist.h" 1 3 4
# 26 "/usr/include/bits/sys_errlist.h" 3 4
extern int sys_nerr;
extern const char *const sys_errlist[];
# 782 "/usr/include/stdio.h" 2 3 4




extern int fileno (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;




extern int fileno_unlocked (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;
# 800 "/usr/include/stdio.h" 3 4
extern FILE *popen (const char *__command, const char *__modes) ;





extern int pclose (FILE *__stream);





extern char *ctermid (char *__s) __attribute__ ((__nothrow__ , __leaf__));
# 840 "/usr/include/stdio.h" 3 4
extern void flockfile (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__));



extern int ftrylockfile (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__)) ;


extern void funlockfile (FILE *__stream) __attribute__ ((__nothrow__ , __leaf__));
# 858 "/usr/include/stdio.h" 3 4
extern int __uflow (FILE *);
extern int __overflow (FILE *, int);
# 873 "/usr/include/stdio.h" 3 4

# 16 "/usr/local/include/win2nix.h" 2 3
#include <stdlib.h>
# 16 "/usr/local/include/win2nix.h" 3
# 1 "/usr/include/stdlib.h" 1 3 4
# 25 "/usr/include/stdlib.h" 3 4
#include <bits/libc-header-start.h>
# 25 "/usr/include/stdlib.h" 3 4
# 1 "/usr/include/bits/libc-header-start.h" 1 3 4
# 33 "/usr/include/bits/libc-header-start.h" 3 4
#include <features.h>
# 26 "/usr/include/stdlib.h" 2 3 4





#include <stddef.h>
# 31 "/usr/include/stdlib.h" 3 4
# 1 "/usr/lib/gcc/x86_64-redhat-linux/9/include/stddef.h" 1 3 4
# 32 "/usr/include/stdlib.h" 2 3 4







#include <bits/waitflags.h>
# 39 "/usr/include/stdlib.h" 3 4
# 1 "/usr/include/bits/waitflags.h" 1 3 4
# 40 "/usr/include/stdlib.h" 2 3 4
#include <bits/waitstatus.h>
# 40 "/usr/include/stdlib.h" 3 4
# 1 "/usr/include/bits/waitstatus.h" 1 3 4
# 41 "/usr/include/stdlib.h" 2 3 4
# 55 "/usr/include/stdlib.h" 3 4
#include <bits/floatn.h>
# 55 "/usr/include/stdlib.h" 3 4
# 1 "/usr/include/bits/floatn.h" 1 3 4
# 22 "/usr/include/bits/floatn.h" 3 4
#include <features.h>
# 119 "/usr/include/bits/floatn.h" 3 4
#include <bits/floatn-common.h>
# 119 "/usr/include/bits/floatn.h" 3 4
# 1 "/usr/include/bits/floatn-common.h" 1 3 4
# 23 "/usr/include/bits/floatn-common.h" 3 4
#include <features.h>
#include <bits/long-double.h>
# 24 "/usr/include/bits/floatn-common.h" 3 4
# 1 "/usr/include/bits/long-double.h" 1 3 4
# 25 "/usr/include/bits/floatn-common.h" 2 3 4
# 120 "/usr/include/bits/floatn.h" 2 3 4
# 56 "/usr/include/stdlib.h" 2 3 4


typedef struct
  {
    int quot;
    int rem;
  } div_t;



typedef struct
  {
    long int quot;
    long int rem;
  } ldiv_t;





__extension__ typedef struct
  {
    long long int quot;
    long long int rem;
  } lldiv_t;
# 97 "/usr/include/stdlib.h" 3 4
extern size_t __ctype_get_mb_cur_max (void) __attribute__ ((__nothrow__ , __leaf__)) ;



extern double atof (const char *__nptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1))) ;

extern int atoi (const char *__nptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1))) ;

extern long int atol (const char *__nptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1))) ;



__extension__ extern long long int atoll (const char *__nptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1))) ;



extern double strtod (const char *__restrict __nptr,
        char **__restrict __endptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));



extern float strtof (const char *__restrict __nptr,
       char **__restrict __endptr) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));

extern long double strtold (const char *__restrict __nptr,
       char **__restrict __endptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
# 176 "/usr/include/stdlib.h" 3 4
extern long int strtol (const char *__restrict __nptr,
   char **__restrict __endptr, int __base)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));

extern unsigned long int strtoul (const char *__restrict __nptr,
      char **__restrict __endptr, int __base)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));



__extension__
extern long long int strtoq (const char *__restrict __nptr,
        char **__restrict __endptr, int __base)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));

__extension__
extern unsigned long long int strtouq (const char *__restrict __nptr,
           char **__restrict __endptr, int __base)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));




__extension__
extern long long int strtoll (const char *__restrict __nptr,
         char **__restrict __endptr, int __base)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));

__extension__
extern unsigned long long int strtoull (const char *__restrict __nptr,
     char **__restrict __endptr, int __base)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
# 385 "/usr/include/stdlib.h" 3 4
extern char *l64a (long int __n) __attribute__ ((__nothrow__ , __leaf__)) ;


extern long int a64l (const char *__s)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1))) ;




#include <sys/types.h>
# 394 "/usr/include/stdlib.h" 3 4
# 1 "/usr/include/sys/types.h" 1 3 4
# 25 "/usr/include/sys/types.h" 3 4
#include <features.h>



#include <bits/types.h>



typedef __u_char u_char;
typedef __u_short u_short;
typedef __u_int u_int;
typedef __u_long u_long;
typedef __quad_t quad_t;
typedef __u_quad_t u_quad_t;
typedef __fsid_t fsid_t;


typedef __loff_t loff_t;




typedef __ino_t ino_t;
# 59 "/usr/include/sys/types.h" 3 4
typedef __dev_t dev_t;




typedef __gid_t gid_t;




typedef __mode_t mode_t;




typedef __nlink_t nlink_t;




typedef __uid_t uid_t;
# 97 "/usr/include/sys/types.h" 3 4
typedef __pid_t pid_t;





typedef __id_t id_t;
# 114 "/usr/include/sys/types.h" 3 4
typedef __daddr_t daddr_t;
typedef __caddr_t caddr_t;





typedef __key_t key_t;




#include <bits/types/clock_t.h>
# 126 "/usr/include/sys/types.h" 3 4
# 1 "/usr/include/bits/types/clock_t.h" 1 3 4



#include <bits/types.h>


typedef __clock_t clock_t;
# 127 "/usr/include/sys/types.h" 2 3 4

#include <bits/types/clockid_t.h>
# 128 "/usr/include/sys/types.h" 3 4
# 1 "/usr/include/bits/types/clockid_t.h" 1 3 4



#include <bits/types.h>


typedef __clockid_t clockid_t;
# 129 "/usr/include/sys/types.h" 2 3 4
#include <bits/types/time_t.h>
# 129 "/usr/include/sys/types.h" 3 4
# 1 "/usr/include/bits/types/time_t.h" 1 3 4



#include <bits/types.h>


typedef __time_t time_t;
# 130 "/usr/include/sys/types.h" 2 3 4
#include <bits/types/timer_t.h>
# 130 "/usr/include/sys/types.h" 3 4
# 1 "/usr/include/bits/types/timer_t.h" 1 3 4



#include <bits/types.h>


typedef __timer_t timer_t;
# 131 "/usr/include/sys/types.h" 2 3 4
# 144 "/usr/include/sys/types.h" 3 4
#include <stddef.h>
# 144 "/usr/include/sys/types.h" 3 4
# 1 "/usr/lib/gcc/x86_64-redhat-linux/9/include/stddef.h" 1 3 4
# 145 "/usr/include/sys/types.h" 2 3 4



typedef unsigned long int ulong;
typedef unsigned short int ushort;
typedef unsigned int uint;




#include <bits/stdint-intn.h>


typedef __uint8_t u_int8_t;
typedef __uint16_t u_int16_t;
typedef __uint32_t u_int32_t;
typedef __uint64_t u_int64_t;


typedef int register_t __attribute__ ((__mode__ (__word__)));
# 176 "/usr/include/sys/types.h" 3 4
#include <endian.h>
# 176 "/usr/include/sys/types.h" 3 4
# 1 "/usr/include/endian.h" 1 3 4
# 21 "/usr/include/endian.h" 3 4
#include <features.h>
# 36 "/usr/include/endian.h" 3 4
#include <bits/endian.h>
# 36 "/usr/include/endian.h" 3 4
# 1 "/usr/include/bits/endian.h" 1 3 4
# 37 "/usr/include/endian.h" 2 3 4
# 60 "/usr/include/endian.h" 3 4
#include <bits/byteswap.h>
# 60 "/usr/include/endian.h" 3 4
# 1 "/usr/include/bits/byteswap.h" 1 3 4
# 26 "/usr/include/bits/byteswap.h" 3 4
#include <features.h>
#include <bits/types.h>





static __inline __uint16_t
__bswap_16 (__uint16_t __bsx)
{

  return __builtin_bswap16 (__bsx);



}






static __inline __uint32_t
__bswap_32 (__uint32_t __bsx)
{

  return __builtin_bswap32 (__bsx);



}
# 69 "/usr/include/bits/byteswap.h" 3 4
__extension__ static __inline __uint64_t
__bswap_64 (__uint64_t __bsx)
{

  return __builtin_bswap64 (__bsx);



}
# 61 "/usr/include/endian.h" 2 3 4
#include <bits/uintn-identity.h>
# 61 "/usr/include/endian.h" 3 4
# 1 "/usr/include/bits/uintn-identity.h" 1 3 4
# 26 "/usr/include/bits/uintn-identity.h" 3 4
#include <bits/types.h>





static __inline __uint16_t
__uint16_identity (__uint16_t __x)
{
  return __x;
}

static __inline __uint32_t
__uint32_identity (__uint32_t __x)
{
  return __x;
}

static __inline __uint64_t
__uint64_identity (__uint64_t __x)
{
  return __x;
}
# 62 "/usr/include/endian.h" 2 3 4
# 177 "/usr/include/sys/types.h" 2 3 4


#include <sys/select.h>
# 179 "/usr/include/sys/types.h" 3 4
# 1 "/usr/include/sys/select.h" 1 3 4
# 24 "/usr/include/sys/select.h" 3 4
#include <features.h>


#include <bits/types.h>


#include <bits/select.h>
# 30 "/usr/include/sys/select.h" 3 4
# 1 "/usr/include/bits/select.h" 1 3 4
# 22 "/usr/include/bits/select.h" 3 4
#include <bits/wordsize.h>
# 22 "/usr/include/bits/select.h" 3 4
# 1 "/usr/include/bits/wordsize.h" 1 3 4
# 23 "/usr/include/bits/select.h" 2 3 4
# 31 "/usr/include/sys/select.h" 2 3 4


#include <bits/types/sigset_t.h>
# 33 "/usr/include/sys/select.h" 3 4
# 1 "/usr/include/bits/types/sigset_t.h" 1 3 4



#include <bits/types/__sigset_t.h>
# 4 "/usr/include/bits/types/sigset_t.h" 3 4
# 1 "/usr/include/bits/types/__sigset_t.h" 1 3 4




typedef struct
{
  unsigned long int __val[(1024 / (8 * sizeof (unsigned long int)))];
} __sigset_t;
# 5 "/usr/include/bits/types/sigset_t.h" 2 3 4


typedef __sigset_t sigset_t;
# 34 "/usr/include/sys/select.h" 2 3 4


#include <bits/types/time_t.h>
#include <bits/types/struct_timeval.h>
# 37 "/usr/include/sys/select.h" 3 4
# 1 "/usr/include/bits/types/struct_timeval.h" 1 3 4



#include <bits/types.h>



struct timeval
{
  __time_t tv_sec;
  __suseconds_t tv_usec;
};
# 38 "/usr/include/sys/select.h" 2 3 4

#include <bits/types/struct_timespec.h>
# 39 "/usr/include/sys/select.h" 3 4
# 1 "/usr/include/bits/types/struct_timespec.h" 1 3 4




#include <bits/types.h>



struct timespec
{
  __time_t tv_sec;
  __syscall_slong_t tv_nsec;
};
# 40 "/usr/include/sys/select.h" 2 3 4



typedef __suseconds_t suseconds_t;





typedef long int __fd_mask;
# 59 "/usr/include/sys/select.h" 3 4
typedef struct
  {






    __fd_mask __fds_bits[1024 / (8 * (int) sizeof (__fd_mask))];


  } fd_set;






typedef __fd_mask fd_mask;
# 91 "/usr/include/sys/select.h" 3 4

# 101 "/usr/include/sys/select.h" 3 4
extern int select (int __nfds, fd_set *__restrict __readfds,
     fd_set *__restrict __writefds,
     fd_set *__restrict __exceptfds,
     struct timeval *__restrict __timeout);
# 113 "/usr/include/sys/select.h" 3 4
extern int pselect (int __nfds, fd_set *__restrict __readfds,
      fd_set *__restrict __writefds,
      fd_set *__restrict __exceptfds,
      const struct timespec *__restrict __timeout,
      const __sigset_t *__restrict __sigmask);
# 126 "/usr/include/sys/select.h" 3 4

# 180 "/usr/include/sys/types.h" 2 3 4





typedef __blksize_t blksize_t;






typedef __blkcnt_t blkcnt_t;



typedef __fsblkcnt_t fsblkcnt_t;



typedef __fsfilcnt_t fsfilcnt_t;
# 227 "/usr/include/sys/types.h" 3 4
#include <bits/pthreadtypes.h>
# 227 "/usr/include/sys/types.h" 3 4
# 1 "/usr/include/bits/pthreadtypes.h" 1 3 4
# 23 "/usr/include/bits/pthreadtypes.h" 3 4
#include <bits/thread-shared-types.h>
# 23 "/usr/include/bits/pthreadtypes.h" 3 4
# 1 "/usr/include/bits/thread-shared-types.h" 1 3 4
# 77 "/usr/include/bits/thread-shared-types.h" 3 4
#include <bits/pthreadtypes-arch.h>
# 77 "/usr/include/bits/thread-shared-types.h" 3 4
# 1 "/usr/include/bits/pthreadtypes-arch.h" 1 3 4
# 21 "/usr/include/bits/pthreadtypes-arch.h" 3 4
#include <bits/wordsize.h>
# 21 "/usr/include/bits/pthreadtypes-arch.h" 3 4
# 1 "/usr/include/bits/wordsize.h" 1 3 4
# 22 "/usr/include/bits/pthreadtypes-arch.h" 2 3 4
# 65 "/usr/include/bits/pthreadtypes-arch.h" 3 4
struct __pthread_rwlock_arch_t
{
  unsigned int __readers;
  unsigned int __writers;
  unsigned int __wrphase_futex;
  unsigned int __writers_futex;
  unsigned int __pad3;
  unsigned int __pad4;

  int __cur_writer;
  int __shared;
  signed char __rwelision;




  unsigned char __pad1[7];


  unsigned long int __pad2;


  unsigned int __flags;
# 99 "/usr/include/bits/pthreadtypes-arch.h" 3 4
};
# 78 "/usr/include/bits/thread-shared-types.h" 2 3 4




typedef struct __pthread_internal_list
{
  struct __pthread_internal_list *__prev;
  struct __pthread_internal_list *__next;
} __pthread_list_t;
# 118 "/usr/include/bits/thread-shared-types.h" 3 4
struct __pthread_mutex_s
{
  int __lock ;
  unsigned int __count;
  int __owner;

  unsigned int __nusers;
# 148 "/usr/include/bits/thread-shared-types.h" 3 4
  int __kind;
 




  short __spins; short __elision;
  __pthread_list_t __list;
# 165 "/usr/include/bits/thread-shared-types.h" 3 4
 
};




struct __pthread_cond_s
{
  __extension__ union
  {
    __extension__ unsigned long long int __wseq;
    struct
    {
      unsigned int __low;
      unsigned int __high;
    } __wseq32;
  };
  __extension__ union
  {
    __extension__ unsigned long long int __g1_start;
    struct
    {
      unsigned int __low;
      unsigned int __high;
    } __g1_start32;
  };
  unsigned int __g_refs[2] ;
  unsigned int __g_size[2];
  unsigned int __g1_orig_size;
  unsigned int __wrefs;
  unsigned int __g_signals[2];
};
# 24 "/usr/include/bits/pthreadtypes.h" 2 3 4



typedef unsigned long int pthread_t;




typedef union
{
  char __size[4];
  int __align;
} pthread_mutexattr_t;




typedef union
{
  char __size[4];
  int __align;
} pthread_condattr_t;



typedef unsigned int pthread_key_t;



typedef int pthread_once_t;


union pthread_attr_t
{
  char __size[56];
  long int __align;
};

typedef union pthread_attr_t pthread_attr_t;




typedef union
{
  struct __pthread_mutex_s __data;
  char __size[40];
  long int __align;
} pthread_mutex_t;


typedef union
{
  struct __pthread_cond_s __data;
  char __size[48];
  __extension__ long long int __align;
} pthread_cond_t;





typedef union
{
  struct __pthread_rwlock_arch_t __data;
  char __size[56];
  long int __align;
} pthread_rwlock_t;

typedef union
{
  char __size[8];
  long int __align;
} pthread_rwlockattr_t;





typedef volatile int pthread_spinlock_t;




typedef union
{
  char __size[32];
  long int __align;
} pthread_barrier_t;

typedef union
{
  char __size[4];
  int __align;
} pthread_barrierattr_t;
# 228 "/usr/include/sys/types.h" 2 3 4



# 395 "/usr/include/stdlib.h" 2 3 4






extern long int random (void) __attribute__ ((__nothrow__ , __leaf__));


extern void srandom (unsigned int __seed) __attribute__ ((__nothrow__ , __leaf__));





extern char *initstate (unsigned int __seed, char *__statebuf,
   size_t __statelen) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2)));



extern char *setstate (char *__statebuf) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));







struct random_data
  {
    int32_t *fptr;
    int32_t *rptr;
    int32_t *state;
    int rand_type;
    int rand_deg;
    int rand_sep;
    int32_t *end_ptr;
  };

extern int random_r (struct random_data *__restrict __buf,
       int32_t *__restrict __result) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));

extern int srandom_r (unsigned int __seed, struct random_data *__buf)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2)));

extern int initstate_r (unsigned int __seed, char *__restrict __statebuf,
   size_t __statelen,
   struct random_data *__restrict __buf)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2, 4)));

extern int setstate_r (char *__restrict __statebuf,
         struct random_data *__restrict __buf)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));





extern int rand (void) __attribute__ ((__nothrow__ , __leaf__));

extern void srand (unsigned int __seed) __attribute__ ((__nothrow__ , __leaf__));



extern int rand_r (unsigned int *__seed) __attribute__ ((__nothrow__ , __leaf__));







extern double drand48 (void) __attribute__ ((__nothrow__ , __leaf__));
extern double erand48 (unsigned short int __xsubi[3]) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern long int lrand48 (void) __attribute__ ((__nothrow__ , __leaf__));
extern long int nrand48 (unsigned short int __xsubi[3])
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern long int mrand48 (void) __attribute__ ((__nothrow__ , __leaf__));
extern long int jrand48 (unsigned short int __xsubi[3])
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern void srand48 (long int __seedval) __attribute__ ((__nothrow__ , __leaf__));
extern unsigned short int *seed48 (unsigned short int __seed16v[3])
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern void lcong48 (unsigned short int __param[7]) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));





struct drand48_data
  {
    unsigned short int __x[3];
    unsigned short int __old_x[3];
    unsigned short int __c;
    unsigned short int __init;
    __extension__ unsigned long long int __a;

  };


extern int drand48_r (struct drand48_data *__restrict __buffer,
        double *__restrict __result) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern int erand48_r (unsigned short int __xsubi[3],
        struct drand48_data *__restrict __buffer,
        double *__restrict __result) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern int lrand48_r (struct drand48_data *__restrict __buffer,
        long int *__restrict __result)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern int nrand48_r (unsigned short int __xsubi[3],
        struct drand48_data *__restrict __buffer,
        long int *__restrict __result)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern int mrand48_r (struct drand48_data *__restrict __buffer,
        long int *__restrict __result)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern int jrand48_r (unsigned short int __xsubi[3],
        struct drand48_data *__restrict __buffer,
        long int *__restrict __result)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern int srand48_r (long int __seedval, struct drand48_data *__buffer)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2)));

extern int seed48_r (unsigned short int __seed16v[3],
       struct drand48_data *__buffer) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));

extern int lcong48_r (unsigned short int __param[7],
        struct drand48_data *__buffer)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));




extern void *malloc (size_t __size) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__malloc__))
     __attribute__ ((__alloc_size__ (1))) ;

extern void *calloc (size_t __nmemb, size_t __size)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__malloc__)) __attribute__ ((__alloc_size__ (1, 2))) ;






extern void *realloc (void *__ptr, size_t __size)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__warn_unused_result__)) __attribute__ ((__alloc_size__ (2)));







extern void *reallocarray (void *__ptr, size_t __nmemb, size_t __size)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__warn_unused_result__))
     __attribute__ ((__alloc_size__ (2, 3)));



extern void free (void *__ptr) __attribute__ ((__nothrow__ , __leaf__));


#include <alloca.h>
# 568 "/usr/include/stdlib.h" 3 4
# 1 "/usr/include/alloca.h" 1 3 4
# 21 "/usr/include/alloca.h" 3 4
#include <features.h>


#include <stddef.h>
# 24 "/usr/include/alloca.h" 3 4
# 1 "/usr/lib/gcc/x86_64-redhat-linux/9/include/stddef.h" 1 3 4
# 25 "/usr/include/alloca.h" 2 3 4







extern void *alloca (size_t __size) __attribute__ ((__nothrow__ , __leaf__));






# 569 "/usr/include/stdlib.h" 2 3 4





extern void *valloc (size_t __size) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__malloc__))
     __attribute__ ((__alloc_size__ (1))) ;




extern int posix_memalign (void **__memptr, size_t __alignment, size_t __size)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) ;




extern void *aligned_alloc (size_t __alignment, size_t __size)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__malloc__)) __attribute__ ((__alloc_size__ (2))) ;



extern void abort (void) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__));



extern int atexit (void (*__func) (void)) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));







extern int at_quick_exit (void (*__func) (void)) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));






extern int on_exit (void (*__func) (int __status, void *__arg), void *__arg)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));





extern void exit (int __status) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__));





extern void quick_exit (int __status) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__));





extern void _Exit (int __status) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__));




extern char *getenv (const char *__name) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) ;
# 647 "/usr/include/stdlib.h" 3 4
extern int putenv (char *__string) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));





extern int setenv (const char *__name, const char *__value, int __replace)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2)));


extern int unsetenv (const char *__name) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));






extern int clearenv (void) __attribute__ ((__nothrow__ , __leaf__));
# 675 "/usr/include/stdlib.h" 3 4
extern char *mktemp (char *__template) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
# 688 "/usr/include/stdlib.h" 3 4
extern int mkstemp (char *__template) __attribute__ ((__nonnull__ (1))) ;
# 710 "/usr/include/stdlib.h" 3 4
extern int mkstemps (char *__template, int __suffixlen) __attribute__ ((__nonnull__ (1))) ;
# 731 "/usr/include/stdlib.h" 3 4
extern char *mkdtemp (char *__template) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) ;
# 784 "/usr/include/stdlib.h" 3 4
extern int system (const char *__command) ;
# 800 "/usr/include/stdlib.h" 3 4
extern char *realpath (const char *__restrict __name,
         char *__restrict __resolved) __attribute__ ((__nothrow__ , __leaf__)) ;






typedef int (*__compar_fn_t) (const void *, const void *);
# 820 "/usr/include/stdlib.h" 3 4
extern void *bsearch (const void *__key, const void *__base,
        size_t __nmemb, size_t __size, __compar_fn_t __compar)
     __attribute__ ((__nonnull__ (1, 2, 5))) ;







extern void qsort (void *__base, size_t __nmemb, size_t __size,
     __compar_fn_t __compar) __attribute__ ((__nonnull__ (1, 4)));
# 840 "/usr/include/stdlib.h" 3 4
extern int abs (int __x) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__)) ;
extern long int labs (long int __x) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__)) ;


__extension__ extern long long int llabs (long long int __x)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__)) ;






extern div_t div (int __numer, int __denom)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__)) ;
extern ldiv_t ldiv (long int __numer, long int __denom)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__)) ;


__extension__ extern lldiv_t lldiv (long long int __numer,
        long long int __denom)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__)) ;
# 872 "/usr/include/stdlib.h" 3 4
extern char *ecvt (double __value, int __ndigit, int *__restrict __decpt,
     int *__restrict __sign) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3, 4))) ;




extern char *fcvt (double __value, int __ndigit, int *__restrict __decpt,
     int *__restrict __sign) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3, 4))) ;




extern char *gcvt (double __value, int __ndigit, char *__buf)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3))) ;




extern char *qecvt (long double __value, int __ndigit,
      int *__restrict __decpt, int *__restrict __sign)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3, 4))) ;
extern char *qfcvt (long double __value, int __ndigit,
      int *__restrict __decpt, int *__restrict __sign)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3, 4))) ;
extern char *qgcvt (long double __value, int __ndigit, char *__buf)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3))) ;




extern int ecvt_r (double __value, int __ndigit, int *__restrict __decpt,
     int *__restrict __sign, char *__restrict __buf,
     size_t __len) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3, 4, 5)));
extern int fcvt_r (double __value, int __ndigit, int *__restrict __decpt,
     int *__restrict __sign, char *__restrict __buf,
     size_t __len) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3, 4, 5)));

extern int qecvt_r (long double __value, int __ndigit,
      int *__restrict __decpt, int *__restrict __sign,
      char *__restrict __buf, size_t __len)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3, 4, 5)));
extern int qfcvt_r (long double __value, int __ndigit,
      int *__restrict __decpt, int *__restrict __sign,
      char *__restrict __buf, size_t __len)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3, 4, 5)));





extern int mblen (const char *__s, size_t __n) __attribute__ ((__nothrow__ , __leaf__));


extern int mbtowc (wchar_t *__restrict __pwc,
     const char *__restrict __s, size_t __n) __attribute__ ((__nothrow__ , __leaf__));


extern int wctomb (char *__s, wchar_t __wchar) __attribute__ ((__nothrow__ , __leaf__));



extern size_t mbstowcs (wchar_t *__restrict __pwcs,
   const char *__restrict __s, size_t __n) __attribute__ ((__nothrow__ , __leaf__));

extern size_t wcstombs (char *__restrict __s,
   const wchar_t *__restrict __pwcs, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__));







extern int rpmatch (const char *__response) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) ;
# 957 "/usr/include/stdlib.h" 3 4
extern int getsubopt (char **__restrict __optionp,
        char *const *__restrict __tokens,
        char **__restrict __valuep)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2, 3))) ;
# 1003 "/usr/include/stdlib.h" 3 4
extern int getloadavg (double __loadavg[], int __nelem)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
# 1013 "/usr/include/stdlib.h" 3 4
#include <bits/stdlib-float.h>
# 1013 "/usr/include/stdlib.h" 3 4
# 1 "/usr/include/bits/stdlib-float.h" 1 3 4
# 1014 "/usr/include/stdlib.h" 2 3 4
# 1023 "/usr/include/stdlib.h" 3 4

# 17 "/usr/local/include/win2nix.h" 2 3
#include <string.h>
# 17 "/usr/local/include/win2nix.h" 3
# 1 "/usr/include/string.h" 1 3 4
# 26 "/usr/include/string.h" 3 4
#include <bits/libc-header-start.h>
# 26 "/usr/include/string.h" 3 4
# 1 "/usr/include/bits/libc-header-start.h" 1 3 4
# 33 "/usr/include/bits/libc-header-start.h" 3 4
#include <features.h>
# 27 "/usr/include/string.h" 2 3 4






#include <stddef.h>
# 33 "/usr/include/string.h" 3 4
# 1 "/usr/lib/gcc/x86_64-redhat-linux/9/include/stddef.h" 1 3 4
# 34 "/usr/include/string.h" 2 3 4
# 43 "/usr/include/string.h" 3 4
extern void *memcpy (void *__restrict __dest, const void *__restrict __src,
       size_t __n) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern void *memmove (void *__dest, const void *__src, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));





extern void *memccpy (void *__restrict __dest, const void *__restrict __src,
        int __c, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));




extern void *memset (void *__s, int __c, size_t __n) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int memcmp (const void *__s1, const void *__s2, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));
# 91 "/usr/include/string.h" 3 4
extern void *memchr (const void *__s, int __c, size_t __n)
      __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1)));
# 122 "/usr/include/string.h" 3 4
extern char *strcpy (char *__restrict __dest, const char *__restrict __src)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));

extern char *strncpy (char *__restrict __dest,
        const char *__restrict __src, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern char *strcat (char *__restrict __dest, const char *__restrict __src)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));

extern char *strncat (char *__restrict __dest, const char *__restrict __src,
        size_t __n) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern int strcmp (const char *__s1, const char *__s2)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));

extern int strncmp (const char *__s1, const char *__s2, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));


extern int strcoll (const char *__s1, const char *__s2)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));

extern size_t strxfrm (char *__restrict __dest,
         const char *__restrict __src, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2)));



#include <bits/types/locale_t.h>
# 153 "/usr/include/string.h" 3 4
# 1 "/usr/include/bits/types/locale_t.h" 1 3 4
# 22 "/usr/include/bits/types/locale_t.h" 3 4
#include <bits/types/__locale_t.h>
# 22 "/usr/include/bits/types/locale_t.h" 3 4
# 1 "/usr/include/bits/types/__locale_t.h" 1 3 4
# 28 "/usr/include/bits/types/__locale_t.h" 3 4
struct __locale_struct
{

  struct __locale_data *__locales[13];


  const unsigned short int *__ctype_b;
  const int *__ctype_tolower;
  const int *__ctype_toupper;


  const char *__names[13];
};

typedef struct __locale_struct *__locale_t;
# 23 "/usr/include/bits/types/locale_t.h" 2 3 4

typedef __locale_t locale_t;
# 154 "/usr/include/string.h" 2 3 4


extern int strcoll_l (const char *__s1, const char *__s2, locale_t __l)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2, 3)));


extern size_t strxfrm_l (char *__dest, const char *__src, size_t __n,
    locale_t __l) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2, 4)));





extern char *strdup (const char *__s)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__malloc__)) __attribute__ ((__nonnull__ (1)));






extern char *strndup (const char *__string, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__malloc__)) __attribute__ ((__nonnull__ (1)));
# 226 "/usr/include/string.h" 3 4
extern char *strchr (const char *__s, int __c)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1)));
# 253 "/usr/include/string.h" 3 4
extern char *strrchr (const char *__s, int __c)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1)));
# 273 "/usr/include/string.h" 3 4
extern size_t strcspn (const char *__s, const char *__reject)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));


extern size_t strspn (const char *__s, const char *__accept)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));
# 303 "/usr/include/string.h" 3 4
extern char *strpbrk (const char *__s, const char *__accept)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));
# 330 "/usr/include/string.h" 3 4
extern char *strstr (const char *__haystack, const char *__needle)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));




extern char *strtok (char *__restrict __s, const char *__restrict __delim)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2)));



extern char *__strtok_r (char *__restrict __s,
    const char *__restrict __delim,
    char **__restrict __save_ptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2, 3)));

extern char *strtok_r (char *__restrict __s, const char *__restrict __delim,
         char **__restrict __save_ptr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2, 3)));
# 385 "/usr/include/string.h" 3 4
extern size_t strlen (const char *__s)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1)));




extern size_t strnlen (const char *__string, size_t __maxlen)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1)));




extern char *strerror (int __errnum) __attribute__ ((__nothrow__ , __leaf__));
# 410 "/usr/include/string.h" 3 4
extern int strerror_r (int __errnum, char *__buf, size_t __buflen) __asm__ ("" "__xpg_strerror_r") __attribute__ ((__nothrow__ , __leaf__))

                        __attribute__ ((__nonnull__ (2)));
# 428 "/usr/include/string.h" 3 4
extern char *strerror_l (int __errnum, locale_t __l) __attribute__ ((__nothrow__ , __leaf__));



#include <strings.h>
# 432 "/usr/include/string.h" 3 4
# 1 "/usr/include/strings.h" 1 3 4
# 21 "/usr/include/strings.h" 3 4
#include <features.h>

#include <stddef.h>
# 23 "/usr/include/strings.h" 3 4
# 1 "/usr/lib/gcc/x86_64-redhat-linux/9/include/stddef.h" 1 3 4
# 24 "/usr/include/strings.h" 2 3 4










extern int bcmp (const void *__s1, const void *__s2, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));


extern void bcopy (const void *__src, void *__dest, size_t __n)
  __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern void bzero (void *__s, size_t __n) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
# 68 "/usr/include/strings.h" 3 4
extern char *index (const char *__s, int __c)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1)));
# 96 "/usr/include/strings.h" 3 4
extern char *rindex (const char *__s, int __c)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1)));






extern int ffs (int __i) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));





extern int ffsl (long int __l) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));
__extension__ extern int ffsll (long long int __ll)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));



extern int strcasecmp (const char *__s1, const char *__s2)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));


extern int strncasecmp (const char *__s1, const char *__s2, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2)));



#include <bits/types/locale_t.h>


extern int strcasecmp_l (const char *__s1, const char *__s2, locale_t __loc)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2, 3)));



extern int strncasecmp_l (const char *__s1, const char *__s2,
     size_t __n, locale_t __loc)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1, 2, 4)));



# 433 "/usr/include/string.h" 2 3 4



extern void explicit_bzero (void *__s, size_t __n) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));



extern char *strsep (char **__restrict __stringp,
       const char *__restrict __delim)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));




extern char *strsignal (int __sig) __attribute__ ((__nothrow__ , __leaf__));


extern char *__stpcpy (char *__restrict __dest, const char *__restrict __src)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern char *stpcpy (char *__restrict __dest, const char *__restrict __src)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));



extern char *__stpncpy (char *__restrict __dest,
   const char *__restrict __src, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
extern char *stpncpy (char *__restrict __dest,
        const char *__restrict __src, size_t __n)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));
# 499 "/usr/include/string.h" 3 4

# 18 "/usr/local/include/win2nix.h" 2 3
#include <assert.h>
# 18 "/usr/local/include/win2nix.h" 3
# 1 "/usr/include/assert.h" 1 3 4
# 35 "/usr/include/assert.h" 3 4
#include <features.h>
# 64 "/usr/include/assert.h" 3 4



extern void __assert_fail (const char *__assertion, const char *__file,
      unsigned int __line, const char *__function)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__));


extern void __assert_perror_fail (int __errnum, const char *__file,
      unsigned int __line, const char *__function)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__));




extern void __assert (const char *__assertion, const char *__file, int __line)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__));



# 19 "/usr/local/include/win2nix.h" 2 3
# 31 "/usr/local/include/win2nix.h" 3
#include <dlfcn.h>
# 31 "/usr/local/include/win2nix.h" 3
# 1 "/usr/include/dlfcn.h" 1 3 4
# 22 "/usr/include/dlfcn.h" 3 4
#include <features.h>

#include <stddef.h>
# 24 "/usr/include/dlfcn.h" 3 4
# 1 "/usr/lib/gcc/x86_64-redhat-linux/9/include/stddef.h" 1 3 4
# 25 "/usr/include/dlfcn.h" 2 3 4


#include <bits/dlfcn.h>
# 27 "/usr/include/dlfcn.h" 3 4
# 1 "/usr/include/bits/dlfcn.h" 1 3 4
# 28 "/usr/include/dlfcn.h" 2 3 4
# 52 "/usr/include/dlfcn.h" 3 4




extern void *dlopen (const char *__file, int __mode) __attribute__ ((__nothrow__));



extern int dlclose (void *__handle) __attribute__ ((__nothrow__)) __attribute__ ((__nonnull__ (1)));



extern void *dlsym (void *__restrict __handle,
      const char *__restrict __name) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2)));
# 82 "/usr/include/dlfcn.h" 3 4
extern char *dlerror (void) __attribute__ ((__nothrow__ , __leaf__));
# 200 "/usr/include/dlfcn.h" 3 4

# 32 "/usr/local/include/win2nix.h" 2 3
#include <sys/time.h>
# 32 "/usr/local/include/win2nix.h" 3
# 1 "/usr/include/sys/time.h" 1 3 4
# 21 "/usr/include/sys/time.h" 3 4
#include <features.h>

#include <bits/types.h>
#include <bits/types/time_t.h>
#include <bits/types/struct_timeval.h>






#include <sys/select.h>


# 52 "/usr/include/sys/time.h" 3 4
struct timezone
  {
    int tz_minuteswest;
    int tz_dsttime;
  };

typedef struct timezone *__restrict __timezone_ptr_t;
# 68 "/usr/include/sys/time.h" 3 4
extern int gettimeofday (struct timeval *__restrict __tv,
    __timezone_ptr_t __tz) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));




extern int settimeofday (const struct timeval *__tv,
    const struct timezone *__tz)
     __attribute__ ((__nothrow__ , __leaf__));





extern int adjtime (const struct timeval *__delta,
      struct timeval *__olddelta) __attribute__ ((__nothrow__ , __leaf__));




enum __itimer_which
  {

    ITIMER_REAL = 0,


    ITIMER_VIRTUAL = 1,



    ITIMER_PROF = 2

  };



struct itimerval
  {

    struct timeval it_interval;

    struct timeval it_value;
  };






typedef int __itimer_which_t;




extern int getitimer (__itimer_which_t __which,
        struct itimerval *__value) __attribute__ ((__nothrow__ , __leaf__));




extern int setitimer (__itimer_which_t __which,
        const struct itimerval *__restrict __new,
        struct itimerval *__restrict __old) __attribute__ ((__nothrow__ , __leaf__));




extern int utimes (const char *__file, const struct timeval __tvp[2])
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));



extern int lutimes (const char *__file, const struct timeval __tvp[2])
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int futimes (int __fd, const struct timeval __tvp[2]) __attribute__ ((__nothrow__ , __leaf__));
# 186 "/usr/include/sys/time.h" 3 4

# 33 "/usr/local/include/win2nix.h" 2 3
#include <pthread.h>
# 33 "/usr/local/include/win2nix.h" 3
# 1 "/usr/include/pthread.h" 1 3 4
# 21 "/usr/include/pthread.h" 3 4
#include <features.h>
#include <endian.h>
#include <sched.h>
# 23 "/usr/include/pthread.h" 3 4
# 1 "/usr/include/sched.h" 1 3 4
# 22 "/usr/include/sched.h" 3 4
#include <features.h>


#include <bits/types.h>



#include <stddef.h>
# 29 "/usr/include/sched.h" 3 4
# 1 "/usr/lib/gcc/x86_64-redhat-linux/9/include/stddef.h" 1 3 4
# 30 "/usr/include/sched.h" 2 3 4

#include <bits/types/time_t.h>
#include <bits/types/struct_timespec.h>
# 43 "/usr/include/sched.h" 3 4
#include <bits/sched.h>
# 43 "/usr/include/sched.h" 3 4
# 1 "/usr/include/bits/sched.h" 1 3 4
# 74 "/usr/include/bits/sched.h" 3 4
#include <bits/types/struct_sched_param.h>
# 74 "/usr/include/bits/sched.h" 3 4
# 1 "/usr/include/bits/types/struct_sched_param.h" 1 3 4
# 23 "/usr/include/bits/types/struct_sched_param.h" 3 4
struct sched_param
{
  int sched_priority;
};
# 75 "/usr/include/bits/sched.h" 2 3 4


# 96 "/usr/include/bits/sched.h" 3 4

# 44 "/usr/include/sched.h" 2 3 4
#include <bits/cpu-set.h>
# 44 "/usr/include/sched.h" 3 4
# 1 "/usr/include/bits/cpu-set.h" 1 3 4
# 32 "/usr/include/bits/cpu-set.h" 3 4
typedef unsigned long int __cpu_mask;






typedef struct
{
  __cpu_mask __bits[1024 / (8 * sizeof (__cpu_mask))];
} cpu_set_t;
# 115 "/usr/include/bits/cpu-set.h" 3 4


extern int __sched_cpucount (size_t __setsize, const cpu_set_t *__setp)
     __attribute__ ((__nothrow__ , __leaf__));
extern cpu_set_t *__sched_cpualloc (size_t __count) __attribute__ ((__nothrow__ , __leaf__)) ;
extern void __sched_cpufree (cpu_set_t *__set) __attribute__ ((__nothrow__ , __leaf__));


# 45 "/usr/include/sched.h" 2 3 4









extern int sched_setparam (__pid_t __pid, const struct sched_param *__param)
     __attribute__ ((__nothrow__ , __leaf__));


extern int sched_getparam (__pid_t __pid, struct sched_param *__param) __attribute__ ((__nothrow__ , __leaf__));


extern int sched_setscheduler (__pid_t __pid, int __policy,
          const struct sched_param *__param) __attribute__ ((__nothrow__ , __leaf__));


extern int sched_getscheduler (__pid_t __pid) __attribute__ ((__nothrow__ , __leaf__));


extern int sched_yield (void) __attribute__ ((__nothrow__ , __leaf__));


extern int sched_get_priority_max (int __algorithm) __attribute__ ((__nothrow__ , __leaf__));


extern int sched_get_priority_min (int __algorithm) __attribute__ ((__nothrow__ , __leaf__));


extern int sched_rr_get_interval (__pid_t __pid, struct timespec *__t) __attribute__ ((__nothrow__ , __leaf__));
# 129 "/usr/include/sched.h" 3 4

# 24 "/usr/include/pthread.h" 2 3 4
#include <time.h>
# 24 "/usr/include/pthread.h" 3 4
# 1 "/usr/include/time.h" 1 3 4
# 25 "/usr/include/time.h" 3 4
#include <features.h>



#include <stddef.h>
# 29 "/usr/include/time.h" 3 4
# 1 "/usr/lib/gcc/x86_64-redhat-linux/9/include/stddef.h" 1 3 4
# 30 "/usr/include/time.h" 2 3 4



#include <bits/time.h>
# 33 "/usr/include/time.h" 3 4
# 1 "/usr/include/bits/time.h" 1 3 4
# 26 "/usr/include/bits/time.h" 3 4
#include <bits/types.h>
# 34 "/usr/include/time.h" 2 3 4



#include <bits/types/clock_t.h>
#include <bits/types/time_t.h>
#include <bits/types/struct_tm.h>
# 39 "/usr/include/time.h" 3 4
# 1 "/usr/include/bits/types/struct_tm.h" 1 3 4



#include <bits/types.h>


struct tm
{
  int tm_sec;
  int tm_min;
  int tm_hour;
  int tm_mday;
  int tm_mon;
  int tm_year;
  int tm_wday;
  int tm_yday;
  int tm_isdst;


  long int tm_gmtoff;
  const char *tm_zone;




};
# 40 "/usr/include/time.h" 2 3 4


#include <bits/types/struct_timespec.h>



#include <bits/types/clockid_t.h>
#include <bits/types/timer_t.h>
#include <bits/types/struct_itimerspec.h>
# 48 "/usr/include/time.h" 3 4
# 1 "/usr/include/bits/types/struct_itimerspec.h" 1 3 4



#include <bits/types.h>
#include <bits/types/struct_timespec.h>


struct itimerspec
  {
    struct timespec it_interval;
    struct timespec it_value;
  };
# 49 "/usr/include/time.h" 2 3 4
struct sigevent;
# 60 "/usr/include/time.h" 3 4
#include <bits/types/locale_t.h>











extern clock_t clock (void) __attribute__ ((__nothrow__ , __leaf__));


extern time_t time (time_t *__timer) __attribute__ ((__nothrow__ , __leaf__));


extern double difftime (time_t __time1, time_t __time0)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));


extern time_t mktime (struct tm *__tp) __attribute__ ((__nothrow__ , __leaf__));





extern size_t strftime (char *__restrict __s, size_t __maxsize,
   const char *__restrict __format,
   const struct tm *__restrict __tp) __attribute__ ((__nothrow__ , __leaf__));
# 104 "/usr/include/time.h" 3 4
extern size_t strftime_l (char *__restrict __s, size_t __maxsize,
     const char *__restrict __format,
     const struct tm *__restrict __tp,
     locale_t __loc) __attribute__ ((__nothrow__ , __leaf__));
# 119 "/usr/include/time.h" 3 4
extern struct tm *gmtime (const time_t *__timer) __attribute__ ((__nothrow__ , __leaf__));



extern struct tm *localtime (const time_t *__timer) __attribute__ ((__nothrow__ , __leaf__));




extern struct tm *gmtime_r (const time_t *__restrict __timer,
       struct tm *__restrict __tp) __attribute__ ((__nothrow__ , __leaf__));



extern struct tm *localtime_r (const time_t *__restrict __timer,
          struct tm *__restrict __tp) __attribute__ ((__nothrow__ , __leaf__));




extern char *asctime (const struct tm *__tp) __attribute__ ((__nothrow__ , __leaf__));


extern char *ctime (const time_t *__timer) __attribute__ ((__nothrow__ , __leaf__));






extern char *asctime_r (const struct tm *__restrict __tp,
   char *__restrict __buf) __attribute__ ((__nothrow__ , __leaf__));


extern char *ctime_r (const time_t *__restrict __timer,
        char *__restrict __buf) __attribute__ ((__nothrow__ , __leaf__));




extern char *__tzname[2];
extern int __daylight;
extern long int __timezone;




extern char *tzname[2];



extern void tzset (void) __attribute__ ((__nothrow__ , __leaf__));



extern int daylight;
extern long int timezone;





extern int stime (const time_t *__when) __attribute__ ((__nothrow__ , __leaf__));
# 196 "/usr/include/time.h" 3 4
extern time_t timegm (struct tm *__tp) __attribute__ ((__nothrow__ , __leaf__));


extern time_t timelocal (struct tm *__tp) __attribute__ ((__nothrow__ , __leaf__));


extern int dysize (int __year) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));
# 211 "/usr/include/time.h" 3 4
extern int nanosleep (const struct timespec *__requested_time,
        struct timespec *__remaining);



extern int clock_getres (clockid_t __clock_id, struct timespec *__res) __attribute__ ((__nothrow__ , __leaf__));


extern int clock_gettime (clockid_t __clock_id, struct timespec *__tp) __attribute__ ((__nothrow__ , __leaf__));


extern int clock_settime (clockid_t __clock_id, const struct timespec *__tp)
     __attribute__ ((__nothrow__ , __leaf__));






extern int clock_nanosleep (clockid_t __clock_id, int __flags,
       const struct timespec *__req,
       struct timespec *__rem);


extern int clock_getcpuclockid (pid_t __pid, clockid_t *__clock_id) __attribute__ ((__nothrow__ , __leaf__));




extern int timer_create (clockid_t __clock_id,
    struct sigevent *__restrict __evp,
    timer_t *__restrict __timerid) __attribute__ ((__nothrow__ , __leaf__));


extern int timer_delete (timer_t __timerid) __attribute__ ((__nothrow__ , __leaf__));


extern int timer_settime (timer_t __timerid, int __flags,
     const struct itimerspec *__restrict __value,
     struct itimerspec *__restrict __ovalue) __attribute__ ((__nothrow__ , __leaf__));


extern int timer_gettime (timer_t __timerid, struct itimerspec *__value)
     __attribute__ ((__nothrow__ , __leaf__));


extern int timer_getoverrun (timer_t __timerid) __attribute__ ((__nothrow__ , __leaf__));





extern int timespec_get (struct timespec *__ts, int __base)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
# 307 "/usr/include/time.h" 3 4

# 25 "/usr/include/pthread.h" 2 3 4

#include <bits/pthreadtypes.h>
#include <bits/setjmp.h>
# 27 "/usr/include/pthread.h" 3 4
# 1 "/usr/include/bits/setjmp.h" 1 3 4
# 26 "/usr/include/bits/setjmp.h" 3 4
#include <bits/wordsize.h>
# 26 "/usr/include/bits/setjmp.h" 3 4
# 1 "/usr/include/bits/wordsize.h" 1 3 4
# 27 "/usr/include/bits/setjmp.h" 2 3 4




typedef long int __jmp_buf[8];
# 28 "/usr/include/pthread.h" 2 3 4
#include <bits/wordsize.h>
# 28 "/usr/include/pthread.h" 3 4
# 1 "/usr/include/bits/wordsize.h" 1 3 4
# 29 "/usr/include/pthread.h" 2 3 4
#include <bits/types/struct_timespec.h>



enum
{
  PTHREAD_CREATE_JOINABLE,

  PTHREAD_CREATE_DETACHED

};



enum
{
  PTHREAD_MUTEX_TIMED_NP,
  PTHREAD_MUTEX_RECURSIVE_NP,
  PTHREAD_MUTEX_ERRORCHECK_NP,
  PTHREAD_MUTEX_ADAPTIVE_NP

  ,
  PTHREAD_MUTEX_NORMAL = PTHREAD_MUTEX_TIMED_NP,
  PTHREAD_MUTEX_RECURSIVE = PTHREAD_MUTEX_RECURSIVE_NP,
  PTHREAD_MUTEX_ERRORCHECK = PTHREAD_MUTEX_ERRORCHECK_NP,
  PTHREAD_MUTEX_DEFAULT = PTHREAD_MUTEX_NORMAL





};




enum
{
  PTHREAD_MUTEX_STALLED,
  PTHREAD_MUTEX_STALLED_NP = PTHREAD_MUTEX_STALLED,
  PTHREAD_MUTEX_ROBUST,
  PTHREAD_MUTEX_ROBUST_NP = PTHREAD_MUTEX_ROBUST
};





enum
{
  PTHREAD_PRIO_NONE,
  PTHREAD_PRIO_INHERIT,
  PTHREAD_PRIO_PROTECT
};
# 115 "/usr/include/pthread.h" 3 4
enum
{
  PTHREAD_RWLOCK_PREFER_READER_NP,
  PTHREAD_RWLOCK_PREFER_WRITER_NP,
  PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP,
  PTHREAD_RWLOCK_DEFAULT_NP = PTHREAD_RWLOCK_PREFER_READER_NP
};
# 156 "/usr/include/pthread.h" 3 4
enum
{
  PTHREAD_INHERIT_SCHED,

  PTHREAD_EXPLICIT_SCHED

};



enum
{
  PTHREAD_SCOPE_SYSTEM,

  PTHREAD_SCOPE_PROCESS

};



enum
{
  PTHREAD_PROCESS_PRIVATE,

  PTHREAD_PROCESS_SHARED

};
# 191 "/usr/include/pthread.h" 3 4
struct _pthread_cleanup_buffer
{
  void (*__routine) (void *);
  void *__arg;
  int __canceltype;
  struct _pthread_cleanup_buffer *__prev;
};


enum
{
  PTHREAD_CANCEL_ENABLE,

  PTHREAD_CANCEL_DISABLE

};
enum
{
  PTHREAD_CANCEL_DEFERRED,

  PTHREAD_CANCEL_ASYNCHRONOUS

};
# 229 "/usr/include/pthread.h" 3 4





extern int pthread_create (pthread_t *__restrict __newthread,
      const pthread_attr_t *__restrict __attr,
      void *(*__start_routine) (void *),
      void *__restrict __arg) __attribute__ ((__nothrow__)) __attribute__ ((__nonnull__ (1, 3)));





extern void pthread_exit (void *__retval) __attribute__ ((__noreturn__));







extern int pthread_join (pthread_t __th, void **__thread_return);
# 272 "/usr/include/pthread.h" 3 4
extern int pthread_detach (pthread_t __th) __attribute__ ((__nothrow__ , __leaf__));



extern pthread_t pthread_self (void) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));


extern int pthread_equal (pthread_t __thread1, pthread_t __thread2)
  __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__const__));







extern int pthread_attr_init (pthread_attr_t *__attr) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_attr_destroy (pthread_attr_t *__attr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_attr_getdetachstate (const pthread_attr_t *__attr,
     int *__detachstate)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern int pthread_attr_setdetachstate (pthread_attr_t *__attr,
     int __detachstate)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));



extern int pthread_attr_getguardsize (const pthread_attr_t *__attr,
          size_t *__guardsize)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern int pthread_attr_setguardsize (pthread_attr_t *__attr,
          size_t __guardsize)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));



extern int pthread_attr_getschedparam (const pthread_attr_t *__restrict __attr,
           struct sched_param *__restrict __param)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern int pthread_attr_setschedparam (pthread_attr_t *__restrict __attr,
           const struct sched_param *__restrict
           __param) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern int pthread_attr_getschedpolicy (const pthread_attr_t *__restrict
     __attr, int *__restrict __policy)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern int pthread_attr_setschedpolicy (pthread_attr_t *__attr, int __policy)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_attr_getinheritsched (const pthread_attr_t *__restrict
      __attr, int *__restrict __inherit)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern int pthread_attr_setinheritsched (pthread_attr_t *__attr,
      int __inherit)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));



extern int pthread_attr_getscope (const pthread_attr_t *__restrict __attr,
      int *__restrict __scope)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern int pthread_attr_setscope (pthread_attr_t *__attr, int __scope)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_attr_getstackaddr (const pthread_attr_t *__restrict
          __attr, void **__restrict __stackaddr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2))) __attribute__ ((__deprecated__));





extern int pthread_attr_setstackaddr (pthread_attr_t *__attr,
          void *__stackaddr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1))) __attribute__ ((__deprecated__));


extern int pthread_attr_getstacksize (const pthread_attr_t *__restrict
          __attr, size_t *__restrict __stacksize)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));




extern int pthread_attr_setstacksize (pthread_attr_t *__attr,
          size_t __stacksize)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));



extern int pthread_attr_getstack (const pthread_attr_t *__restrict __attr,
      void **__restrict __stackaddr,
      size_t *__restrict __stacksize)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2, 3)));




extern int pthread_attr_setstack (pthread_attr_t *__attr, void *__stackaddr,
      size_t __stacksize) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
# 430 "/usr/include/pthread.h" 3 4
extern int pthread_setschedparam (pthread_t __target_thread, int __policy,
      const struct sched_param *__param)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (3)));


extern int pthread_getschedparam (pthread_t __target_thread,
      int *__restrict __policy,
      struct sched_param *__restrict __param)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2, 3)));


extern int pthread_setschedprio (pthread_t __target_thread, int __prio)
     __attribute__ ((__nothrow__ , __leaf__));
# 495 "/usr/include/pthread.h" 3 4
extern int pthread_once (pthread_once_t *__once_control,
    void (*__init_routine) (void)) __attribute__ ((__nonnull__ (1, 2)));
# 507 "/usr/include/pthread.h" 3 4
extern int pthread_setcancelstate (int __state, int *__oldstate);



extern int pthread_setcanceltype (int __type, int *__oldtype);


extern int pthread_cancel (pthread_t __th);




extern void pthread_testcancel (void);




typedef struct
{
  struct
  {
    __jmp_buf __cancel_jmp_buf;
    int __mask_was_saved;
  } __cancel_jmp_buf[1];
  void *__pad[4];
} __pthread_unwind_buf_t __attribute__ ((__aligned__));
# 541 "/usr/include/pthread.h" 3 4
struct __pthread_cleanup_frame
{
  void (*__cancel_routine) (void *);
  void *__cancel_arg;
  int __do_it;
  int __cancel_type;
};
# 681 "/usr/include/pthread.h" 3 4
extern void __pthread_register_cancel (__pthread_unwind_buf_t *__buf)
     ;
# 693 "/usr/include/pthread.h" 3 4
extern void __pthread_unregister_cancel (__pthread_unwind_buf_t *__buf)
  ;
# 734 "/usr/include/pthread.h" 3 4
extern void __pthread_unwind_next (__pthread_unwind_buf_t *__buf)
     __attribute__ ((__noreturn__))

     __attribute__ ((__weak__))

     ;



struct __jmp_buf_tag;
extern int __sigsetjmp (struct __jmp_buf_tag *__env, int __savemask) __attribute__ ((__nothrow__));





extern int pthread_mutex_init (pthread_mutex_t *__mutex,
          const pthread_mutexattr_t *__mutexattr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_mutex_destroy (pthread_mutex_t *__mutex)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_mutex_trylock (pthread_mutex_t *__mutex)
     __attribute__ ((__nothrow__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_mutex_lock (pthread_mutex_t *__mutex)
     __attribute__ ((__nothrow__)) __attribute__ ((__nonnull__ (1)));



extern int pthread_mutex_timedlock (pthread_mutex_t *__restrict __mutex,
        const struct timespec *__restrict
        __abstime) __attribute__ ((__nothrow__)) __attribute__ ((__nonnull__ (1, 2)));
# 781 "/usr/include/pthread.h" 3 4
extern int pthread_mutex_unlock (pthread_mutex_t *__mutex)
     __attribute__ ((__nothrow__)) __attribute__ ((__nonnull__ (1)));



extern int pthread_mutex_getprioceiling (const pthread_mutex_t *
      __restrict __mutex,
      int *__restrict __prioceiling)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));



extern int pthread_mutex_setprioceiling (pthread_mutex_t *__restrict __mutex,
      int __prioceiling,
      int *__restrict __old_ceiling)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 3)));




extern int pthread_mutex_consistent (pthread_mutex_t *__mutex)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
# 814 "/usr/include/pthread.h" 3 4
extern int pthread_mutexattr_init (pthread_mutexattr_t *__attr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_mutexattr_destroy (pthread_mutexattr_t *__attr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_mutexattr_getpshared (const pthread_mutexattr_t *
      __restrict __attr,
      int *__restrict __pshared)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern int pthread_mutexattr_setpshared (pthread_mutexattr_t *__attr,
      int __pshared)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));



extern int pthread_mutexattr_gettype (const pthread_mutexattr_t *__restrict
          __attr, int *__restrict __kind)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));




extern int pthread_mutexattr_settype (pthread_mutexattr_t *__attr, int __kind)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));



extern int pthread_mutexattr_getprotocol (const pthread_mutexattr_t *
       __restrict __attr,
       int *__restrict __protocol)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));



extern int pthread_mutexattr_setprotocol (pthread_mutexattr_t *__attr,
       int __protocol)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_mutexattr_getprioceiling (const pthread_mutexattr_t *
          __restrict __attr,
          int *__restrict __prioceiling)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern int pthread_mutexattr_setprioceiling (pthread_mutexattr_t *__attr,
          int __prioceiling)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));



extern int pthread_mutexattr_getrobust (const pthread_mutexattr_t *__attr,
     int *__robustness)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));







extern int pthread_mutexattr_setrobust (pthread_mutexattr_t *__attr,
     int __robustness)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
# 896 "/usr/include/pthread.h" 3 4
extern int pthread_rwlock_init (pthread_rwlock_t *__restrict __rwlock,
    const pthread_rwlockattr_t *__restrict
    __attr) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_rwlock_destroy (pthread_rwlock_t *__rwlock)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_rwlock_rdlock (pthread_rwlock_t *__rwlock)
     __attribute__ ((__nothrow__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_rwlock_tryrdlock (pthread_rwlock_t *__rwlock)
  __attribute__ ((__nothrow__)) __attribute__ ((__nonnull__ (1)));



extern int pthread_rwlock_timedrdlock (pthread_rwlock_t *__restrict __rwlock,
           const struct timespec *__restrict
           __abstime) __attribute__ ((__nothrow__)) __attribute__ ((__nonnull__ (1, 2)));
# 927 "/usr/include/pthread.h" 3 4
extern int pthread_rwlock_wrlock (pthread_rwlock_t *__rwlock)
     __attribute__ ((__nothrow__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_rwlock_trywrlock (pthread_rwlock_t *__rwlock)
     __attribute__ ((__nothrow__)) __attribute__ ((__nonnull__ (1)));



extern int pthread_rwlock_timedwrlock (pthread_rwlock_t *__restrict __rwlock,
           const struct timespec *__restrict
           __abstime) __attribute__ ((__nothrow__)) __attribute__ ((__nonnull__ (1, 2)));
# 949 "/usr/include/pthread.h" 3 4
extern int pthread_rwlock_unlock (pthread_rwlock_t *__rwlock)
     __attribute__ ((__nothrow__)) __attribute__ ((__nonnull__ (1)));





extern int pthread_rwlockattr_init (pthread_rwlockattr_t *__attr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_rwlockattr_destroy (pthread_rwlockattr_t *__attr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_rwlockattr_getpshared (const pthread_rwlockattr_t *
       __restrict __attr,
       int *__restrict __pshared)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern int pthread_rwlockattr_setpshared (pthread_rwlockattr_t *__attr,
       int __pshared)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_rwlockattr_getkind_np (const pthread_rwlockattr_t *
       __restrict __attr,
       int *__restrict __pref)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern int pthread_rwlockattr_setkind_np (pthread_rwlockattr_t *__attr,
       int __pref) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));







extern int pthread_cond_init (pthread_cond_t *__restrict __cond,
         const pthread_condattr_t *__restrict __cond_attr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_cond_destroy (pthread_cond_t *__cond)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_cond_signal (pthread_cond_t *__cond)
     __attribute__ ((__nothrow__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_cond_broadcast (pthread_cond_t *__cond)
     __attribute__ ((__nothrow__)) __attribute__ ((__nonnull__ (1)));






extern int pthread_cond_wait (pthread_cond_t *__restrict __cond,
         pthread_mutex_t *__restrict __mutex)
     __attribute__ ((__nonnull__ (1, 2)));
# 1022 "/usr/include/pthread.h" 3 4
extern int pthread_cond_timedwait (pthread_cond_t *__restrict __cond,
       pthread_mutex_t *__restrict __mutex,
       const struct timespec *__restrict __abstime)
     __attribute__ ((__nonnull__ (1, 2, 3)));
# 1045 "/usr/include/pthread.h" 3 4
extern int pthread_condattr_init (pthread_condattr_t *__attr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_condattr_destroy (pthread_condattr_t *__attr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_condattr_getpshared (const pthread_condattr_t *
     __restrict __attr,
     int *__restrict __pshared)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern int pthread_condattr_setpshared (pthread_condattr_t *__attr,
     int __pshared) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));



extern int pthread_condattr_getclock (const pthread_condattr_t *
          __restrict __attr,
          __clockid_t *__restrict __clock_id)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern int pthread_condattr_setclock (pthread_condattr_t *__attr,
          __clockid_t __clock_id)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
# 1081 "/usr/include/pthread.h" 3 4
extern int pthread_spin_init (pthread_spinlock_t *__lock, int __pshared)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_spin_destroy (pthread_spinlock_t *__lock)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_spin_lock (pthread_spinlock_t *__lock)
     __attribute__ ((__nothrow__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_spin_trylock (pthread_spinlock_t *__lock)
     __attribute__ ((__nothrow__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_spin_unlock (pthread_spinlock_t *__lock)
     __attribute__ ((__nothrow__)) __attribute__ ((__nonnull__ (1)));






extern int pthread_barrier_init (pthread_barrier_t *__restrict __barrier,
     const pthread_barrierattr_t *__restrict
     __attr, unsigned int __count)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_barrier_destroy (pthread_barrier_t *__barrier)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_barrier_wait (pthread_barrier_t *__barrier)
     __attribute__ ((__nothrow__)) __attribute__ ((__nonnull__ (1)));



extern int pthread_barrierattr_init (pthread_barrierattr_t *__attr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_barrierattr_destroy (pthread_barrierattr_t *__attr)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_barrierattr_getpshared (const pthread_barrierattr_t *
        __restrict __attr,
        int *__restrict __pshared)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1, 2)));


extern int pthread_barrierattr_setpshared (pthread_barrierattr_t *__attr,
        int __pshared)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
# 1148 "/usr/include/pthread.h" 3 4
extern int pthread_key_create (pthread_key_t *__key,
          void (*__destr_function) (void *))
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));


extern int pthread_key_delete (pthread_key_t __key) __attribute__ ((__nothrow__ , __leaf__));


extern void *pthread_getspecific (pthread_key_t __key) __attribute__ ((__nothrow__ , __leaf__));


extern int pthread_setspecific (pthread_key_t __key,
    const void *__pointer) __attribute__ ((__nothrow__ , __leaf__)) ;




extern int pthread_getcpuclockid (pthread_t __thread_id,
      __clockid_t *__clock_id)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (2)));
# 1182 "/usr/include/pthread.h" 3 4
extern int pthread_atfork (void (*__prepare) (void),
      void (*__parent) (void),
      void (*__child) (void)) __attribute__ ((__nothrow__ , __leaf__));
# 1196 "/usr/include/pthread.h" 3 4

# 34 "/usr/local/include/win2nix.h" 2 3

typedef void* HMODULE;

static HMODULE LoadLibrary(const char* path)
{
 return dlopen(path, 0x00002);
}

static BOOL FreeLibrary(HMODULE module)
{

 return !dlclose(module);
}

static ptrdiff_t GetProcAddress(HMODULE module, const char* proc_name)
{
 return (ptrdiff_t)(dlsym(module, proc_name));
}
# 66 "/usr/local/include/win2nix.h" 3
static const char DEFAULTLIBRARYNAME[] = "./librtpkcs11ecp.so";
# 36 "/usr/local/include/Common.h" 2 3
# 72 "/usr/local/include/Common.h" 3
static const char* rvToStr(CK_RV rv)
{
 switch (rv) {
 case 0x00000000: return "CKR_OK";
 case 0x00000001: return "CKR_CANCEL";
 case 0x00000002: return "CKR_HOST_MEMORY";
 case 0x00000003: return "CKR_SLOT_ID_INVALID";
 case 0x00000005: return "CKR_GENERAL_ERROR";
 case 0x00000006: return "CKR_FUNCTION_FAILED";
 case 0x00000007: return "CKR_ARGUMENTS_BAD";
 case 0x00000008: return "CKR_NO_EVENT";
 case 0x00000009: return "CKR_NEED_TO_CREATE_THREADS";
 case 0x0000000A: return "CKR_CANT_LOCK";
 case 0x00000010: return "CKR_ATTRIBUTE_READ_ONLY";
 case 0x00000011: return "CKR_ATTRIBUTE_SENSITIVE";
 case 0x00000012: return "CKR_ATTRIBUTE_TYPE_INVALID";
 case 0x00000013: return "CKR_ATTRIBUTE_VALUE_INVALID";
 case 0x00000020: return "CKR_DATA_INVALID";
 case 0x00000021: return "CKR_DATA_LEN_RANGE";
 case 0x00000030: return "CKR_DEVICE_ERROR";
 case 0x00000031: return "CKR_DEVICE_MEMORY";
 case 0x00000032: return "CKR_DEVICE_REMOVED";
 case 0x00000040: return "CKR_ENCRYPTED_DATA_INVALID";
 case 0x00000041: return "CKR_ENCRYPTED_DATA_LEN_RANGE";
 case 0x00000050: return "CKR_FUNCTION_CANCELED";
 case 0x00000051: return "CKR_FUNCTION_NOT_PARALLEL";
 case 0x00000054: return "CKR_FUNCTION_NOT_SUPPORTED";
 case 0x00000060: return "CKR_KEY_HANDLE_INVALID";
 case 0x00000062: return "CKR_KEY_SIZE_RANGE";
 case 0x00000063: return "CKR_KEY_TYPE_INCONSISTENT";
 case 0x00000064: return "CKR_KEY_NOT_NEEDED";
 case 0x00000065: return "CKR_KEY_CHANGED";
 case 0x00000066: return "CKR_KEY_NEEDED";
 case 0x00000067: return "CKR_KEY_INDIGESTIBLE";
 case 0x00000068: return "CKR_KEY_FUNCTION_NOT_PERMITTED";
 case 0x00000069: return "CKR_KEY_NOT_WRAPPABLE";
 case 0x0000006A: return "CKR_KEY_UNEXTRACTABLE";
 case 0x00000070: return "CKR_MECHANISM_INVALID";
 case 0x00000071: return "CKR_MECHANISM_PARAM_INVALID";
 case 0x00000082: return "CKR_OBJECT_HANDLE_INVALID";
 case 0x00000090: return "CKR_OPERATION_ACTIVE";
 case 0x00000091: return "CKR_OPERATION_NOT_INITIALIZED";
 case 0x000000A0: return "CKR_PIN_INCORRECT";
 case 0x000000A1: return "CKR_PIN_INVALID";
 case 0x000000A2: return "CKR_PIN_LEN_RANGE";
 case 0x000000A3: return "CKR_PIN_EXPIRED";
 case 0x000000A4: return "CKR_PIN_LOCKED";
 case 0x000000B0: return "CKR_SESSION_CLOSED";
 case 0x000000B1: return "CKR_SESSION_COUNT";
 case 0x000000B3: return "CKR_SESSION_HANDLE_INVALID";
 case 0x000000B4: return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
 case 0x000000B5: return "CKR_SESSION_READ_ONLY";
 case 0x000000B6: return "CKR_SESSION_EXISTS";
 case 0x000000B7: return "CKR_SESSION_READ_ONLY_EXISTS";
 case 0x000000B8: return "CKR_SESSION_READ_WRITE_SO_EXISTS";
 case 0x000000C0: return "CKR_SIGNATURE_INVALID";
 case 0x000000C1: return "CKR_SIGNATURE_LEN_RANGE";
 case 0x000000D0: return "CKR_TEMPLATE_INCOMPLETE";
 case 0x000000D1: return "CKR_TEMPLATE_INCONSISTENT";
 case 0x000000E0: return "CKR_TOKEN_NOT_PRESENT";
 case 0x000000E1: return "CKR_TOKEN_NOT_RECOGNIZED";
 case 0x000000E2: return "CKR_TOKEN_WRITE_PROTECTED";
 case 0x000000F0: return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
 case 0x000000F1: return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
 case 0x000000F2: return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
 case 0x00000100: return "CKR_USER_ALREADY_LOGGED_IN";
 case 0x00000101: return "CKR_USER_NOT_LOGGED_IN";
 case 0x00000102: return "CKR_USER_PIN_NOT_INITIALIZED";
 case 0x00000103: return "CKR_USER_TYPE_INVALID";
 case 0x00000104: return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
 case 0x00000105: return "CKR_USER_TOO_MANY_TYPES";
 case 0x00000110: return "CKR_WRAPPED_KEY_INVALID";
 case 0x00000112: return "CKR_WRAPPED_KEY_LEN_RANGE";
 case 0x00000113: return "CKR_WRAPPING_KEY_HANDLE_INVALID";
 case 0x00000114: return "CKR_WRAPPING_KEY_SIZE_RANGE";
 case 0x00000115: return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
 case 0x00000120: return "CKR_RANDOM_SEED_NOT_SUPPORTED";
 case 0x00000121: return "CKR_RANDOM_NO_RNG";
 case 0x00000130: return "CKR_DOMAIN_PARAMS_INVALID";
 case 0x00000150: return "CKR_BUFFER_TOO_SMALL";
 case 0x00000160: return "CKR_SAVED_STATE_INVALID";
 case 0x00000170: return "CKR_INFORMATION_SENSITIVE";
 case 0x00000180: return "CKR_STATE_UNSAVEABLE";
 case 0x00000190: return "CKR_CRYPTOKI_NOT_INITIALIZED";
 case 0x00000191: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
 case 0x000001A0: return "CKR_MUTEX_BAD";
 case 0x000001A1: return "CKR_MUTEX_NOT_LOCKED";
 case 0x000001B0: return "CKR_NEW_PIN_MODE";
 case 0x000001B1: return "CKR_NEXT_OTP";
 case 0x00000200: return "CKR_FUNCTION_REJECTED";
 case (0x80000000 +1): return "CKR_CORRUPTED_MAPFILE";
 case (0x80000000 +2): return "CKR_WRONG_VERSION_FIELD";
 case (0x80000000 +3): return "CKR_WRONG_PKCS1_ENCODING";
 case (0x80000000 +4): return "CKR_RTPKCS11_DATA_CORRUPTED";
 case (0x80000000 +5): return "CKR_RTPKCS11_RSF_DATA_CORRUPTED";
 case (0x80000000 +6): return "CKR_SM_PASSWORD_INVALID";
 case (0x80000000 +7): return "CKR_LICENSE_READ_ONLY";
 default: return "Unknown error";
 }
}
# 233 "/usr/local/include/Common.h" 3
static void printHex(const CK_BYTE* buffer,
                     const CK_ULONG length)
{
 unsigned int i;
 const unsigned int width = 16;
 for (i = 0; i < length; ++i) {
  if (i % width == 0) {
   printf("   ");
  }

  printf("%02X ", buffer[i]);

  if ((i + 1) % width == 0 || (i + 1) == length) {
   printf("\n");
  }
 }
}




static CK_BYTE GetNext6Bit(CK_BYTE_PTR csr,
                    CK_ULONG start,
                    CK_ULONG end
                    )
{
 CK_BYTE diff = start % 8;
 csr += start / 8;
 if (end - start > 8) {
  return 0x3F & (*csr << diff | *(csr + 1) >> (8 - diff)) >> 2;
 } else {
  return 0x3F & (*csr << diff >> 2);
 }
}




static char ConvertCodeToSymBase64(CK_BYTE code
                            )
{
 const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 if (code < 0x40) {
  return alphabet[(int)code];
 } else {
  return '?';
 }
}




static void ConvertToBase64String(CK_BYTE_PTR data,
                           CK_ULONG size,
                           char** result
                           )
{
 CK_ULONG i = 0;
 char* pt;
 *result = (char*)calloc(((size_t)size + 2) / 3 * 4 + 1, sizeof(char));
 if (*result != ((void *)0)) {
  memset(*result, '=', ((size_t)size + 2) / 3 * 4);
  for (pt = *result; i < size * 8; i += 6, ++pt) {
   *pt = ConvertCodeToSymBase64(GetNext6Bit(data, i, size * 8));
  }
 }
}




static void GetBytesAsPem(CK_BYTE_PTR source,
                CK_ULONG size,
                const char* header,
                const char* footer,
                char** result
                   )
{
 size_t length;
 size_t width = 0x40;
 char* buffer;
 size_t i;

 ConvertToBase64String(source, size, &buffer);
 if (buffer == ((void *)0)) {
  *result = ((void *)0);
  return;
 }
 length = strlen(buffer);
 *result = (char*)calloc(strlen(header)
  + length
  + strlen(footer)
  + (length - 1) / width + 1
  + 1,
  sizeof(char));
 if (*result == ((void *)0)) {
  free(buffer);
  return;
 }

 strcat(*result, header);
 for (i = 0; i < length; i += width) {
  strncat(*result, buffer + i, width);
  strcat(*result, "\n");
 }
 strcat(*result, footer);

 free(buffer);
}




static void GetCSRAsPEM(CK_BYTE_PTR source,
                  CK_ULONG size,
                  char** result
                  )
{
 const char* begin = "-----BEGIN NEW CERTIFICATE REQUEST-----\n";
 const char* end = "-----END NEW CERTIFICATE REQUEST-----\n";

 GetBytesAsPem(source, size, begin, end, result);
}




static void GetCMSAsPEM(CK_BYTE_PTR source,
                  CK_ULONG size,
                  char** result
                  )
{
        const char* begin = "-----BEGIN CMS-----\n";
        const char* end = "-----END CMS-----\n";

        GetBytesAsPem(source, size, begin, end, result);
}




static void GetCertAsPem(CK_BYTE_PTR source,
               CK_ULONG size,
               char** result
)
{
 const char* begin = "-----BEGIN CERTIFICATE-----\n";
 const char* end = "-----END CERTIFICATE-----\n";

 GetBytesAsPem(source, size, begin, end, result);
}





static int printUTF8String(CK_BYTE* info)
{
# 447 "/usr/local/include/Common.h" 3
 printf("%s", info);
 return 0;

}
# 12 "ex1_change_pin.c" 2
#include "utils.h"
# 12 "ex1_change_pin.c"
# 1 "utils.h" 1
# 14 "utils.h"
#include <Common.h>


# 16 "utils.h"
extern CK_FUNCTION_LIST_PTR functionList;
extern CK_FUNCTION_LIST_EXTENDED_PTR functionListEx;


int init_pkcs11();

int free_pkcs11();

int get_slot_list(CK_SLOT_ID_PTR* slots_ptr, CK_ULONG_PTR slotCount);


int findObjects(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR attributes, CK_ULONG attrCount,
                CK_OBJECT_HANDLE objects[], CK_ULONG* objectsCount);


int find_private_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR privateKey);

int find_public_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR publicKey);

int find_certificate(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR certificate);


int mech_supports(CK_SLOT_ID slot, CK_MECHANISM_TYPE mech, int* mechIsSupported);
# 13 "ex1_change_pin.c" 2

int change_pin_code(CK_SLOT_ID slot, char* oldPin, char* newPin);

int main(void)
{
 CK_SLOT_ID_PTR slots;
 CK_ULONG slotCount;
 char* oldPin = "12345678";
 char* newPin = "12345678";

 CK_RV rv;
 int errorCode = 1;


 if (init_pkcs11())
  goto exit;


 if (get_slot_list(&slots, &slotCount))
  goto free_pkcs11;

 if (slotCount == 0) {
  printf("No token found\n");
  goto free_slots;
 }


 if (change_pin_code(slots[0], oldPin, newPin))
  goto free_slots;


 errorCode = 0;




free_slots:
 free(slots);




free_pkcs11:
 free_pkcs11();

exit:
 if (errorCode) {
  printf("\n\nSome error occurred. Sample failed.\n");
 } else {
  printf("\n\nSample has been completed successfully.\n");
 }

 return errorCode;
}

int change_pin_code(CK_SLOT_ID slot, char* oldPin, char* newPin)
{
 CK_SESSION_HANDLE session;
 CK_RV rv;
 int errorCode = 1;




 rv = functionList->C_OpenSession(slot, 
# 77 "ex1_change_pin.c" 3
                                       0x00000004 
# 77 "ex1_change_pin.c"
                                                          | 
# 77 "ex1_change_pin.c" 3
                                                            0x00000002
# 77 "ex1_change_pin.c"
                                                                          , 
# 77 "ex1_change_pin.c" 3
                                                                            0
# 77 "ex1_change_pin.c"
                                                                                    , 
# 77 "ex1_change_pin.c" 3
                                                                                      0
# 77 "ex1_change_pin.c"
                                                                                              , &session);
 
# 78 "ex1_change_pin.c" 3
do { printf("%s", 
# 78 "ex1_change_pin.c"
" C_OpenSession"
# 78 "ex1_change_pin.c" 3
); if (!(
# 78 "ex1_change_pin.c"
rv == 
# 78 "ex1_change_pin.c" 3
0x00000000)) { printf(" -> Failed\n%s\n", 
# 78 "ex1_change_pin.c"
rvToStr(rv)
# 78 "ex1_change_pin.c" 3
); goto 
# 78 "ex1_change_pin.c"
exit
# 78 "ex1_change_pin.c" 3
; } else { printf(" -> OK\n"); } } while (0)
# 78 "ex1_change_pin.c"
                                                                ;




 rv = functionList->C_Login(session, 
# 83 "ex1_change_pin.c" 3
                                    1
# 83 "ex1_change_pin.c"
                                            , oldPin, strlen(oldPin));
 
# 84 "ex1_change_pin.c" 3
do { printf("%s", 
# 84 "ex1_change_pin.c"
" C_Login (CKU_USER)"
# 84 "ex1_change_pin.c" 3
); if (!(
# 84 "ex1_change_pin.c"
rv == 
# 84 "ex1_change_pin.c" 3
0x00000000)) { printf(" -> Failed\n%s\n", 
# 84 "ex1_change_pin.c"
rvToStr(rv)
# 84 "ex1_change_pin.c" 3
); goto 
# 84 "ex1_change_pin.c"
close_session
# 84 "ex1_change_pin.c" 3
; } else { printf(" -> OK\n"); } } while (0)
# 84 "ex1_change_pin.c"
                                                                              ;




 printf("\nChanging user PIN to default...\n");

 rv = functionList->C_SetPIN(session, 
# 91 "ex1_change_pin.c" 3
                                     0
# 91 "ex1_change_pin.c"
                                             , 0, newPin, strlen(newPin));
 
# 92 "ex1_change_pin.c" 3
do { printf("%s", 
# 92 "ex1_change_pin.c"
" C_SetPIN"
# 92 "ex1_change_pin.c" 3
); if (!(
# 92 "ex1_change_pin.c"
rv == 
# 92 "ex1_change_pin.c" 3
0x00000000)) { printf(" -> Failed\n%s\n", 
# 92 "ex1_change_pin.c"
rvToStr(rv)
# 92 "ex1_change_pin.c" 3
); goto 
# 92 "ex1_change_pin.c"
logout
# 92 "ex1_change_pin.c" 3
; } else { printf(" -> OK\n"); } } while (0)
# 92 "ex1_change_pin.c"
                                                             ;

 printf("User PIN has been changed to default successfully.\n");

 errorCode = 0;




logout:
 rv = functionList->C_Logout(session);
 
# 103 "ex1_change_pin.c" 3
do { printf("%s", 
# 103 "ex1_change_pin.c"
" C_Logout"
# 103 "ex1_change_pin.c" 3
); if (!(
# 103 "ex1_change_pin.c"
rv == 
# 103 "ex1_change_pin.c" 3
0x00000000)) { printf(" -> Failed\n%s\n", 
# 103 "ex1_change_pin.c"
rvToStr(rv)
# 103 "ex1_change_pin.c" 3
); 
# 103 "ex1_change_pin.c"
errorCode 
# 103 "ex1_change_pin.c" 3
= 1; } else { printf(" -> OK\n"); } } while (0)
# 103 "ex1_change_pin.c"
                                                                        ;




close_session:
 rv = functionList->C_CloseSession(session);
 
# 110 "ex1_change_pin.c" 3
do { printf("%s", 
# 110 "ex1_change_pin.c"
" C_CloseSession"
# 110 "ex1_change_pin.c" 3
); if (!(
# 110 "ex1_change_pin.c"
rv == 
# 110 "ex1_change_pin.c" 3
0x00000000)) { printf(" -> Failed\n%s\n", 
# 110 "ex1_change_pin.c"
rvToStr(rv)
# 110 "ex1_change_pin.c" 3
); 
# 110 "ex1_change_pin.c"
errorCode 
# 110 "ex1_change_pin.c" 3
= 1; } else { printf(" -> OK\n"); } } while (0)
# 110 "ex1_change_pin.c"
                                                                              ;
exit:
 return errorCode;
}
