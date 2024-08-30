import cython
cimport cython


from libc.stdlib cimport malloc
from libc.stdlib cimport free
from libc.string cimport memcpy
from libc.stdio cimport printf

from cpython.bytes cimport PyBytes_AsString

import re

class Pkcs11Exception(Exception):
    pass


cdef extern from "stdint.h":
    ctypedef unsigned long long uintptr_t

cdef extern from "stdlib.h":
  ctypedef int atoi_type(const char *)

cdef extern from "dlfcn.h":
  void *dlopen(const char *filename, int flags)
  cdef int RTLD_NOW
  void *dlsym(void *handle, const char *symbol)
  char *dlerror()


cdef extern:
    ctypedef void * CK_VOID_PTR
    ctypedef CK_VOID_PTR * CK_VOID_PTR_PTR

    ctypedef unsigned long int CK_ULONG
    ctypedef CK_ULONG CK_RV
    ctypedef CK_ULONG CK_SLOT_ID
    ctypedef CK_ULONG *CK_ULONG_PTR
    ctypedef CK_ULONG CK_FLAGS
    ctypedef CK_ULONG CK_OBJECT_HANDLE
    ctypedef CK_ULONG CK_SESSION_HANDLE
    ctypedef CK_ULONG CK_STATE
    ctypedef CK_ULONG CK_KEY_TYPE

    ctypedef unsigned char CK_BYTE
    ctypedef CK_BYTE CK_BBOOL
    ctypedef CK_BYTE CK_UTF8CHAR
    ctypedef CK_BYTE *CK_BYTE_PTR
    ctypedef CK_BYTE CK_CHAR

    ctypedef unsigned long int size_t

    ctypedef CK_SLOT_ID *CK_SLOT_ID_PTR
    ctypedef CK_SLOT_ID_PTR *CK_SLOT_ID_PTR_PTR

    struct CK_VERSION:
        CK_BYTE major
        CK_BYTE minor

    ctypedef CK_INFO *CK_INFO_PTR

    ctypedef CK_UTF8CHAR * CK_UTF8CHAR_PTR

    ctypedef CK_RUTOKEN_INIT_PARAM * CK_RUTOKEN_INIT_PARAM_PTR
  
    ctypedef CK_RV ( * CK_C_Finalize ) ( CK_VOID_PTR pReserved )
    ctypedef CK_RV ( * CK_C_Initialize ) ( CK_VOID_PTR pInitArgs )
    ctypedef CK_RV ( * CK_C_GetInfo ) ( CK_INFO_PTR pInfo)
    ctypedef CK_RV ( * CK_C_GetSlotList) ( CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount )


    ctypedef CK_FUNCTION_LIST_EXTENDED *CK_FUNCTION_LIST_EXTENDED_PTR

    
    ctypedef CK_FUNCTION_LIST * CK_FUNCTION_LIST_PTR
    ctypedef CK_FUNCTION_LIST_PTR * CK_FUNCTION_LIST_PTR_PTR
    ctypedef CK_RV ( * CK_C_GetFunctionList) ( CK_FUNCTION_LIST_PTR_PTR ppFunctionList )

    ctypedef CK_FUNCTION_LIST_EXTENDED * CK_FUNCTION_LIST_EXTENDED_PTR
    ctypedef CK_FUNCTION_LIST_EXTENDED_PTR * CK_FUNCTION_LIST_EXTENDED_PTR_PTR
    ctypedef CK_RV ( * CK_C_EX_GetFunctionListExtended) ( CK_FUNCTION_LIST_EXTENDED_PTR_PTR ppFunctionList )
    ctypedef CK_RV ( * CK_C_EX_InitToken) ( CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_RUTOKEN_INIT_PARAM_PTR pInitInfo )

    ctypedef CK_ULONG CK_SLOT_ID

    ctypedef CK_RV ( * CK_CREATEMUTEX)  (CK_VOID_PTR_PTR)
    ctypedef CK_RV ( * CK_DESTROYMUTEX) (CK_VOID_PTR_PTR)
    ctypedef CK_RV ( * CK_LOCKMUTEX)    (CK_VOID_PTR_PTR)
    ctypedef CK_RV ( * CK_UNLOCKMUTEX)  (CK_VOID_PTR_PTR)

    ctypedef CK_ULONG CK_FLAGS

    ctypedef CK_SLOT_INFO * CK_SLOT_INFO_PTR
    ctypedef CK_RV ( * CK_C_GetSlotInfo ) ( CK_SLOT_ID slotID , CK_SLOT_INFO_PTR pInfo )

    ctypedef CK_TOKEN_INFO * CK_TOKEN_INFO_PTR
    ctypedef CK_RV ( * CK_C_GetTokenInfo) ( CK_SLOT_ID slotID , CK_TOKEN_INFO_PTR pInfo)

    ctypedef CK_ULONG CK_MECHANISM_TYPE
    ctypedef CK_MECHANISM_TYPE * CK_MECHANISM_TYPE_PTR
    ctypedef CK_MECHANISM_TYPE_PTR pMechanismList
    ctypedef CK_RV ( * CK_C_GetMechanismList) ( CK_SLOT_ID slotID , CK_MECHANISM_TYPE_PTR pMechanismList , CK_ULONG_PTR pulCount )

    ctypedef CK_ULONG CK_MECHANISM_TYPE
    ctypedef CK_MECHANISM_INFO * CK_MECHANISM_INFO_PTR
    ctypedef CK_MECHANISM_INFO * CK_MECHANISM_INFO_PTR
    ctypedef CK_RV (*CK_C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)

    ctypedef CK_UTF8CHAR * CK_UTF8CHAR_PTR
    ctypedef CK_RV (*CK_C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)

    ctypedef CK_ULONG CK_SESSION_HANDLE
    ctypedef CK_RV (*CK_C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)

    ctypedef CK_RV (*CK_C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)

    ctypedef CK_ULONG CK_NOTIFICATION
    ctypedef CK_RV ( * CK_NOTIFY)(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event, CK_VOID_PTR pApplication )
    ctypedef CK_SESSION_HANDLE * CK_SESSION_HANDLE_PTR
    ctypedef CK_RV (*CK_C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)

    ctypedef CK_RV (*CK_C_CloseSession)(CK_SESSION_HANDLE hSession)

    ctypedef CK_RV (*CK_C_CloseAllSessions)(CK_SLOT_ID slotID)

    ctypedef CK_SESSION_INFO * CK_SESSION_INFO_PTR
    ctypedef CK_RV (*CK_C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)

    ctypedef CK_RV (*CK_C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)

    ctypedef CK_RV (*CK_C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)

    ctypedef CK_ULONG CK_SESSION_HANDLE
    ctypedef CK_ULONG CK_USER_TYPE
    ctypedef CK_RV ( * CK_C_Login) ( CK_SESSION_HANDLE hSession , CK_USER_TYPE userType , CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen )

    ctypedef CK_ATTRIBUTE * CK_ATTRIBUTE_PTR
    ctypedef CK_ULONG CK_ATTRIBUTE_TYPE

    ctypedef CK_ULONG CK_OBJECT_CLASS;

    ctypedef CK_RV(*CK_C_Logout) (CK_SESSION_HANDLE hSession)

    ctypedef CK_OBJECT_HANDLE * CK_OBJECT_HANDLE_PTR
    ctypedef CK_RV(*CK_C_CreateObject) ( CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)

    ctypedef CK_RV (*CK_C_CopyObject) (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,  CK_ATTRIBUTE_PTR pTemplate,  CK_ULONG   ulCount,  CK_OBJECT_HANDLE_PTR phNewObject)

    ctypedef CK_RV(*CK_C_DestroyObject) ( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)

    ctypedef CK_RV(*CK_C_GetObjectSize)( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE  hObject,  CK_ULONG_PTR pulSize)

    ctypedef CK_RV(*CK_C_GetAttributeValue) (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG GulCount)

    ctypedef CK_RV(*CK_C_SetAttributeValue) (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)

    ctypedef CK_RV(*CK_C_FindObjectsInit) ( CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount )

    ctypedef CK_RV(*CK_C_FindObjects) ( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)

    ctypedef CK_RV(*CK_C_FindObjectsFinal)( CK_SESSION_HANDLE hSession )

    ctypedef CK_MECHANISM * CK_MECHANISM_PTR;
    ctypedef CK_RV ( *CK_C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)

    ctypedef CK_RV ( *CK_C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                                    CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)

    ctypedef CK_RV ( *CK_C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                                          CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)

    ctypedef CK_RV ( *CK_C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
                                         CK_ULONG_PTR pulLastEncryptedPartLen)



    ctypedef CK_RV(*CK_C_DecryptInit) (  CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey )

    ctypedef CK_RV(*CK_C_Decrypt) ( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)

    ctypedef CK_RV(*CK_C_DecryptUpdate) ( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen )

    ctypedef CK_RV(*CK_C_DecryptFinal) ( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)

    ctypedef CK_RV(*CK_C_DigestInit) ( CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)

    ctypedef CK_RV(*CK_C_Digest) ( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen )

    ctypedef CK_RV(*CK_C_DigestUpdate) ( CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen )

    ctypedef CK_RV(*CK_C_DigestKey) ( CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)

    ctypedef CK_RV (*CK_C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
    ctypedef CK_RV (*CK_C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
    ctypedef CK_RV (*CK_C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTRpData, CK_ULONGulDataLen, CK_BYTE_PTRpSignature,
                               CK_ULONG_PTRpulSignatureLen)
    ctypedef CK_RV (*CK_C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONGulPartLen)
    ctypedef CK_RV (*CK_C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTRpSignature, CK_ULONG_PTRpulSignatureLen)
    ctypedef CK_RV (*CK_C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLEhKey)
    ctypedef CK_RV (*CK_C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTRpData, CK_ULONGulDataLen,
                                       CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
    ctypedef CK_RV (*CK_C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLEhKey)
    ctypedef CK_RV (*CK_C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                                 CK_ULONG ulSignatureLen)
    ctypedef CK_RV (*CK_C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
    ctypedef CK_RV (*CK_C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
    ctypedef CK_RV (*CK_C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                                            CK_OBJECT_HANDLE hKey)
    ctypedef CK_RV (*CK_C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen,
                                        CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
    ctypedef CK_RV (*CK_C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                                              CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
    ctypedef CK_RV (*CK_C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
                                              CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
    ctypedef CK_RV (*CK_C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
                                            CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
    ctypedef CK_RV (*CK_C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
                                              CK_ULONG GulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
    ctypedef CK_RV (*CK_C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate,
                                      CK_ULONG GulCount, CK_OBJECT_HANDLE_PTR phKey)
    ctypedef CK_RV (*CK_C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                                           CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
                                           CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
                                           CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
    struct CK_INFO:
        CK_VERSION    cryptokiVersion   
        CK_UTF8CHAR   manufacturerID[32]
        CK_FLAGS      flags              
        CK_UTF8CHAR   libraryDescription[32]
        CK_VERSION    libraryVersion  

    struct CK_SLOT_INFO:
        CK_UTF8CHAR slotDescription[64]
        CK_UTF8CHAR manufacturerID[32]
        CK_FLAGS flags
        CK_VERSION hardwareVersion
        CK_VERSION firmwareVersion
    
    struct CK_TOKEN_INFO:
        CK_UTF8CHAR label[32]
        CK_UTF8CHAR manufacturerID[32]
        CK_UTF8CHAR model[16]
        CK_CHAR serialNumber[16]
        CK_FLAGS flags
        CK_ULONG ulMaxSessionCount
        CK_ULONG ulSessionCount
        CK_ULONG ulMaxRwSessionCount
        CK_ULONG ulRwSessionCount
        CK_ULONG ulMaxPinLen
        CK_ULONG ulMinPinLen
        CK_ULONG ulTotalPublicMemory
        CK_ULONG ulFreePublicMemory
        CK_ULONG ulTotalPrivateMemory
        CK_ULONG ulFreePrivateMemory
        CK_VERSION hardwareVersion
        CK_VERSION firmwareVersion
        CK_CHAR utcTime[16]
    
    struct CK_SESSION_INFO:
        CK_SLOT_ID slotID
        CK_STATE state
        CK_FLAGS flags
        CK_ULONG ulDeviceError

    struct CK_FUNCTION_LIST:
        CK_VERSION version
        CK_C_Initialize C_Initialize
        CK_C_Finalize C_Finalize
        CK_C_GetInfo C_GetInfo
        CK_C_GetFunctionList C_GetFunctionList
        CK_C_GetSlotList C_GetSlotList
        CK_C_GetSlotInfo C_GetSlotInfo
        CK_C_GetTokenInfo C_GetTokenInfo
        CK_C_GetMechanismList C_GetMechanismList
        CK_C_GetMechanismInfo C_GetMechanismInfo
        CK_C_InitToken C_InitToken
        CK_C_InitPIN C_InitPIN
        CK_C_SetPIN C_SetPIN
        CK_C_OpenSession C_OpenSession
        CK_C_CloseSession C_CloseSession
        CK_C_CloseAllSessions C_CloseAllSessions
        CK_C_GetSessionInfo C_GetSessionInfo
        CK_C_GetOperationState C_GetOperationState
        CK_C_SetOperationState C_SetOperationState
        CK_C_Login C_Login
        CK_C_Logout C_Logout
        CK_C_CreateObject C_CreateObject;
        CK_C_CopyObject C_CopyObject;
        CK_C_DestroyObject C_DestroyObject;
        CK_C_GetObjectSize C_GetObjectSize;
        CK_C_GetAttributeValue C_GetAttributeValue;
        CK_C_SetAttributeValue C_SetAttributeValue;
        CK_C_FindObjectsInit C_FindObjectsInit;
        CK_C_FindObjects C_FindObjects;
        CK_C_FindObjectsFinal C_FindObjectsFinal;
        CK_C_EncryptInit C_EncryptInit;
        CK_C_Encrypt C_Encrypt;
        CK_C_EncryptUpdate C_EncryptUpdate;
        CK_C_EncryptFinal C_EncryptFinal;
        CK_C_DecryptInit C_DecryptInit;
        CK_C_Decrypt C_Decrypt;
        CK_C_DecryptUpdate C_DecryptUpdate;
        CK_C_DecryptFinal C_DecryptFinal;
        CK_C_DigestInit C_DigestInit;
        CK_C_Digest C_Digest;
        CK_C_DigestUpdate C_DigestUpdate;
        CK_C_DigestKey C_DigestKey;
        CK_C_DigestFinal C_DigestFinal;
        CK_C_SignInit C_SignInit;
        CK_C_Sign C_Sign;
        CK_C_SignUpdate C_SignUpdate;
        CK_C_SignFinal C_SignFinal;
        CK_C_SignRecoverInit C_SignRecoverInit;
        CK_C_SignRecover C_SignRecover;
        CK_C_VerifyInit C_VerifyInit;
        CK_C_Verify C_Verify;
        CK_C_VerifyUpdate C_VerifyUpdate;
        CK_C_VerifyFinal C_VerifyFinal;
        CK_C_VerifyRecoverInit C_VerifyRecoverInit;
        CK_C_VerifyRecover C_VerifyRecover;
        CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
        CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
        CK_C_SignEncryptUpdate C_SignEncryptUpdate;
        CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
        CK_C_GenerateKey C_GenerateKey;
        CK_C_GenerateKeyPair C_GenerateKeyPair;

    struct CK_FUNCTION_LIST_EXTENDED:
        CK_VERSION version
        CK_C_EX_GetFunctionListExtended C_EX_GetFunctionListExtended
        CK_C_EX_InitToken C_EX_InitToken
#        CK_C_EX_GetTokenInfoExtended C_EX_GetTokenInfoExtended
#        CK_C_EX_UnblockUserPIN C_EX_UnblockUserPIN
#        CK_C_EX_SetTokenName C_EX_SetTokenName
#        CK_C_EX_SetLicense C_EX_SetLicense
#        CK_C_EX_GetLicense C_EX_GetLicense
#        CK_C_EX_GetCertificateInfoText C_EX_GetCertificateInfoText
#        CK_C_EX_PKCS7Sign C_EX_PKCS7Sign
#        CK_C_EX_CreateCSR C_EX_CreateCSR
#        CK_C_EX_FreeBuffer C_EX_FreeBuffer
#        CK_C_EX_GetTokenName C_EX_GetTokenName
#        CK_C_EX_SetLocalPIN C_EX_SetLocalPIN
#        CK_C_EX_LoadActivationKey C_EX_LoadActivationKey
#        CK_C_EX_SetActivationPassword C_EX_SetActivationPassword
#        CK_C_EX_GetVolumesInfo C_EX_GetVolumesInfo
#        CK_C_EX_GetDriveSize C_EX_GetDriveSize
#        CK_C_EX_ChangeVolumeAttributes C_EX_ChangeVolumeAttributes
#        CK_C_EX_FormatDrive C_EX_FormatDrive
#        CK_C_EX_TokenManage C_EX_TokenManage
#        CK_C_EX_GenerateActivationPassword C_EX_GenerateActivationPassword
#        CK_C_EX_GetJournal C_EX_GetJournal
#        CK_C_EX_SignInvisibleInit C_EX_SignInvisibleInit
#        CK_C_EX_SignInvisible C_EX_SignInvisible
#        CK_C_EX_SlotManage C_EX_SlotManage
#        CK_C_EX_WrapKey C_EX_WrapKey
#        CK_C_EX_UnwrapKey C_EX_UnwrapKey
#        CK_C_EX_PKCS7VerifyInit C_EX_PKCS7VerifyInit
#        CK_C_EX_PKCS7Verify C_EX_PKCS7Verify
#        CK_C_EX_PKCS7VerifyUpdate C_EX_PKCS7VerifyUpdate
#        CK_C_EX_PKCS7VerifyFinal C_EX_PKCS7VerifyFinal


    struct CK_C_INITIALIZE_ARGS:
        CK_CREATEMUTEX CreateMutex
        CK_DESTROYMUTEX DestroyMutex
        CK_LOCKMUTEX LockMutex
        CK_UNLOCKMUTEX UnlockMutex
        CK_FLAGS flags
        CK_VOID_PTR pReserved

    struct CK_RUTOKEN_INIT_PARAM:
        CK_ULONG    ulSizeofThisStructure
        CK_ULONG    UseRepairMode
        CK_BYTE_PTR pNewAdminPin
        CK_ULONG    ulNewAdminPinLen
        CK_BYTE_PTR pNewUserPin
        CK_ULONG    ulNewUserPinLen
        CK_FLAGS    ChangeUserPINPolicy
        CK_ULONG    ulMinAdminPinLen
        CK_ULONG    ulMinUserPinLen
        CK_ULONG    ulMaxAdminRetryCount
        CK_ULONG    ulMaxUserRetryCount
        CK_BYTE_PTR pTokenLabel
        CK_ULONG    ulLabelLen
        CK_ULONG    ulSmMode

    struct CK_MECHANISM_INFO:
        CK_ULONG    ulMinKeySize
        CK_ULONG    ulMaxKeySize
        CK_FLAGS    flags

    struct CK_ATTRIBUTE:
        CK_ATTRIBUTE_TYPE type
        CK_VOID_PTR pValue
        CK_ULONG ulValueLen

    struct CK_MECHANISM:
      CK_MECHANISM_TYPE mechanism
      CK_VOID_PTR pParameter
      CK_ULONG ulParameterLen

# cdef CK_FUNCTION_LIST_EXTENDED_PTR functionListEx
# cdef CK_FUNCTION_LIST cfl
# cdef CK_FUNCTION_LIST_PTR functionList
# cdef CK_SLOT_ID_PTR slots


rv2str = {
          0x00 : 'CKR_OK',
          0x01 : 'CKR_CANCEL', 
          0x02 : 'CKR_HOST_MEMORY', 
          0x03 : 'CKR_SLOT_ID_INVALID',
          0x05 : 'CKR_GENERAL_ERROR',
          0x06 : 'CKR_FUNCTION_FAILED',
          0x07 : 'CKR_ARGUMENTS_BAD', 
          0x08 : 'CKR_NO_EVENT', 
          0x09 : 'CKR_NEED_TO_CREATE_THREADS', 
          0x0a : 'CKR_CANT_LOCK', 
          0x10 : 'CKR_ATTRIBUTE_READ_ONLY', 
          0x11 : 'CKR_ATTRIBUTE_SENSITIVE', 
          0x12 : 'CKR_ATTRIBUTE_TYPE_INVALID', 
          0x13 : 'CKR_ATTRIBUTE_VALUE_INVALID', 
          0x20 : 'CKR_DATA_INVALID', 
          0x21 : 'CKR_DATA_LEN_RANGE', 
          0x30 : 'CKR_DEVICE_ERROR', 
          0x31 : 'CKR_DEVICE_MEMORY', 
          0x32 : 'CKR_DEVICE_REMOVED', 
          0x40 : 'CKR_ENCRYPTED_DATA_INVALID', 
          0x41 : 'CKR_ENCRYPTED_DATA_LEN_RANGE', 
          0x50 : 'CKR_FUNCTION_CANCELED', 
          0x51 : 'CKR_FUNCTION_NOT_PARALLEL', 
          0x54 : 'CKR_FUNCTION_NOT_SUPPORTED', 
          0x60 : 'CKR_KEY_HANDLE_INVALID', 
          0x62 : 'CKR_KEY_SIZE_RANGE',
          0x63 : 'CKR_KEY_TYPE_INCONSISTENT', 
          0x64 : 'CKR_KEY_NOT_NEEDED', 
          0x65 : 'CKR_KEY_CHANGED', 
          0x66 : 'CKR_KEY_NEEDED', 
          0x67 : 'CKR_KEY_INDIGESTIBLE', 
          0x68 : 'CKR_KEY_FUNCTION_NOT_PERMITTED', 
          0x69 : 'CKR_KEY_NOT_WRAPPABLE', 
          0x6a : 'CKR_KEY_UNEXTRACTABLE', 
          0x70 : 'CKR_MECHANISM_INVALID', 
          0x71 : 'CKR_MECHANISM_PARAM_INVALID', 
          0x82 : 'CKR_OBJECT_HANDLE_INVALID', 
          0x90 : 'CKR_OPERATION_ACTIVE', 
          0x91 : 'CKR_OPERATION_NOT_INITIALIZED', 
          0xa0 : 'CKR_PIN_INCORRECT', 
          0xa1 : 'CKR_PIN_INVALID', 
          0xa2 : 'CKR_PIN_LEN_RANGE', 
          0xa3 : 'CKR_PIN_EXPIRED', 
          0xa4 : 'CKR_PIN_LOCKED', 
          0xb0 : 'CKR_SESSION_CLOSED', 
          0xb1 : 'CKR_SESSION_COUNT', 
          0xb3 : 'CKR_SESSION_HANDLE_INVALID', 
          0xb4 : 'CKR_SESSION_PARALLEL_NOT_SUPPORTED', 
          0xb5 : 'CKR_SESSION_READ_ONLY', 
          0xb6 : 'CKR_SESSION_EXISTS', 
          0xb7 : 'CKR_SESSION_READ_ONLY_EXISTS', 
          0xb8 : 'CKR_SESSION_READ_WRITE_SO_EXISTS', 
          0xc0 : 'CKR_SIGNATURE_INVALID', 
          0xc1 : 'CKR_SIGNATURE_LEN_RANGE', 
          0xd0 : 'CKR_TEMPLATE_INCOMPLETE', 
          0xd1 : 'CKR_TEMPLATE_INCONSISTENT', 
          0xe0 : 'CKR_TOKEN_NOT_PRESENT', 
          0xe1 : 'CKR_TOKEN_NOT_RECOGNIZED', 
          0xf0 : 'CKR_TOKEN_WRITE_PROTE3NDLE_INVALID', 
          0xf1 : 'CKR_UNWRAPPING_KEY_SIZE_RANGE', 
          0xf2 : 'CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT', 
         0x100 : 'CKR_USER_ALREADY_LOGGED_IN', 
         0x101 : 'CKR_USER_NOT_LOGGED_IN', 
         0x102 : 'CKR_USER_PIN_NOT_INITIALIZED', 
         0x103 : 'CKR_USER_TYPE_INVALID', 
         0x104 : 'CKR_USER_ANOTHER_ALREADY_LOGGED_IN', 
         0x105 : 'CKR_USER_TOO_MANY_TYPES', 
         0x110 : 'CKR_WRAPPED_KEY_INVALID', 
         0x112 : 'CKR_WRAPPED_KEY_LEN_RANGE', 
         0x113 : 'CKR_WRAPPING_KEY_HANDLE_INVALID', 
         0x114 : 'CKR_WRAPPING_KEY_SIZE_RANGE', 
         0x115 : 'CKR_WRAPPING_KEY_TYPE_INCONSISTENT', 
         0x120 : 'CKR_RANDOM_SEED_NOT_SUPPORTED', 
         0x121 : 'CKR_RANDOM_NO_RNG', 
         0x130 : 'CKR_DOMAIN_PARAMS_INVALID', 
         0x150 : 'CKR_BUFFER_TOO_SMALL', 
         0x160 : 'CKR_SAVED_STATE_INVALID', 
         0x170 : 'CKR_INFORMATION_SENSITIVE', 
         0x180 : 'CKR_STATE_UNSAVEABLE', 
         0x190 : 'CKR_CRYPTOKI_NOT_INITIALIZED', 
         0x191 : 'CKR_CRYPTOKI_ALREADY_INITIALIZED', 
         0x1a0 : 'CKR_MUTEX_BAD', 
         0x1a1 : 'CKR_MUTEX_NOT_LOCKED', 
         0x1b0 : 'CKR_NEW_PIN_MODE', 
         0x1b1 : 'CKR_NEXT_OTP', 
         0x200 : 'CKR_FUNCTION_REJECTED', 
    0x80000000 : 'CKR_VENDOR_DEFINED'
    }

mech2str = {
    0x00000000 : 'CKM_RSA_PKCS_KEY_PAIR_GEN', 
    0x00000001 : 'CKM_RSA_PKCS', 
    0x00000002 : 'CKM_RSA_9796', 
    0x00000003 : 'CKM_RSA_X_509', 
    0x00000004 : 'CKM_MD2_RSA_PKCS', 
    0x00000005 : 'CKM_MD5_RSA_PKCS', 
    0x00000006 : 'CKM_SHA1_RSA_PKCS', 
    0x00000007 : 'CKM_RIPEMD128_RSA_PKCS', 
    0x00000008 : 'CKM_RIPEMD160_RSA_PKCS', 
    0x00000009 : 'CKM_RSA_PKCS_OAEP', 
    0x0000000A : 'CKM_RSA_X9_31_KEY_PAIR_GEN', 
    0x0000000B : 'CKM_RSA_X9_31', 
    0x0000000C : 'CKM_SHA1_RSA_X9_31', 
    0x0000000D : 'CKM_RSA_PKCS_PSS', 
    0x0000000E : 'CKM_SHA1_RSA_PKCS_PSS', 
    0x00000010 : 'CKM_DSA_KEY_PAIR_GEN', 
    0x00000011 : 'CKM_DSA', 
    0x00000012 : 'CKM_DSA_SHA1', 
    0x00000020 : 'CKM_DH_PKCS_KEY_PAIR_GEN', 
    0x00000021 : 'CKM_DH_PKCS_DERIVE', 
    0x00000030 : 'CKM_X9_42_DH_KEY_PAIR_GEN', 
    0x00000031 : 'CKM_X9_42_DH_DERIVE', 
    0x00000032 : 'CKM_X9_42_DH_HYBRID_DERIVE', 
    0x00000033 : 'CKM_X9_42_MQV_DERIVE', 
    0x00000040 : 'CKM_SHA256_RSA_PKCS', 
    0x00000041 : 'CKM_SHA384_RSA_PKCS', 
    0x00000042 : 'CKM_SHA512_RSA_PKCS', 
    0x00000043 : 'CKM_SHA256_RSA_PKCS_PSS', 
    0x00000044 : 'CKM_SHA384_RSA_PKCS_PSS', 
    0x00000045 : 'CKM_SHA512_RSA_PKCS_PSS', 
    0x00000046 : 'CKM_SHA224_RSA_PKCS', 
    0x00000047 : 'CKM_SHA224_RSA_PKCS_PSS', 
    0x00000100 : 'CKM_RC2_KEY_GEN', 
    0x00000101 : 'CKM_RC2_ECB', 
    0x00000102 : 'CKM_RC2_CBC', 
    0x00000103 : 'CKM_RC2_MAC', 
    0x00000104 : 'CKM_RC2_MAC_GENERAL', 
    0x00000105 : 'CKM_RC2_CBC_PAD', 
    0x00000110 : 'CKM_RC4_KEY_GEN', 
    0x00000111 : 'CKM_RC4', 
    0x00000120 : 'CKM_DES_KEY_GEN', 
    0x00000121 : 'CKM_DES_ECB', 
    0x00000122 : 'CKM_DES_CBC', 
    0x00000123 : 'CKM_DES_MAC', 
    0x00000124 : 'CKM_DES_MAC_GENERAL', 
    0x00000125 : 'CKM_DES_CBC_PAD', 
    0x00000130 : 'CKM_DES2_KEY_GEN', 
    0x00000131 : 'CKM_DES3_KEY_GEN', 
    0x00000132 : 'CKM_DES3_ECB', 
    0x00000133 : 'CKM_DES3_CBC', 
    0x00000134 : 'CKM_DES3_MAC', 
    0x00000135 : 'CKM_DES3_MAC_GENERAL', 
    0x00000136 : 'CKM_DES3_CBC_PAD', 
    0x00000140 : 'CKM_CDMF_KEY_GEN', 
    0x00000141 : 'CKM_CDMF_ECB', 
    0x00000142 : 'CKM_CDMF_CBC', 
    0x00000143 : 'CKM_CDMF_MAC', 
    0x00000144 : 'CKM_CDMF_MAC_GENERAL', 
    0x00000145 : 'CKM_CDMF_CBC_PAD', 
    0x00000150 : 'CKM_DES_OFB64', 
    0x00000151 : 'CKM_DES_OFB8', 
    0x00000152 : 'CKM_DES_CFB64', 
    0x00000153 : 'CKM_DES_CFB8', 
    0x00000200 : 'CKM_MD2', 
    0x00000201 : 'CKM_MD2_HMAC', 
    0x00000202 : 'CKM_MD2_HMAC_GENERAL', 
    0x00000210 : 'CKM_MD5', 
    0x00000211 : 'CKM_MD5_HMAC', 
    0x00000212 : 'CKM_MD5_HMAC_GENERAL', 
    0x00000220 : 'CKM_SHA_1', 
    0x00000221 : 'CKM_SHA_1_HMAC', 
    0x00000222 : 'CKM_SHA_1_HMAC_GENERAL', 
    0x00000230 : 'CKM_RIPEMD128', 
    0x00000231 : 'CKM_RIPEMD128_HMAC', 
    0x00000232 : 'CKM_RIPEMD128_HMAC_GENERAL', 
    0x00000240 : 'CKM_RIPEMD160', 
    0x00000241 : 'CKM_RIPEMD160_HMAC', 
    0x00000242 : 'CKM_RIPEMD160_HMAC_GENERAL', 
    0x00000250 : 'CKM_SHA256', 
    0x00000251 : 'CKM_SHA256_HMAC', 
    0x00000252 : 'CKM_SHA256_HMAC_GENERAL', 
    0x00000255 : 'CKM_SHA224', 
    0x00000256 : 'CKM_SHA224_HMAC', 
    0x00000257 : 'CKM_SHA224_HMAC_GENERAL', 
    0x00000260 : 'CKM_SHA384', 
    0x00000261 : 'CKM_SHA384_HMAC', 
    0x00000262 : 'CKM_SHA384_HMAC_GENERAL', 
    0x00000270 : 'CKM_SHA512', 
    0x00000271 : 'CKM_SHA512_HMAC', 
    0x00000272 : 'CKM_SHA512_HMAC_GENERAL', 
    0x00000280 : 'CKM_SECURID_KEY_GEN', 
    0x00000282 : 'CKM_SECURID', 
    0x00000290 : 'CKM_HOTP_KEY_GEN', 
    0x00000291 : 'CKM_HOTP', 
    0x000002A0 : 'CKM_ACTI', 
    0x000002A1 : 'CKM_ACTI_KEY_GEN', 
    0x00000300 : 'CKM_CAST_KEY_GEN', 
    0x00000301 : 'CKM_CAST_ECB', 
    0x00000302 : 'CKM_CAST_CBC', 
    0x00000303 : 'CKM_CAST_MAC', 
    0x00000304 : 'CKM_CAST_MAC_GENERAL', 
    0x00000305 : 'CKM_CAST_CBC_PAD', 
    0x00000310 : 'CKM_CAST3_KEY_GEN', 
    0x00000311 : 'CKM_CAST3_ECB', 
    0x00000312 : 'CKM_CAST3_CBC', 
    0x00000313 : 'CKM_CAST3_MAC', 
    0x00000314 : 'CKM_CAST3_MAC_GENERAL', 
    0x00000315 : 'CKM_CAST3_CBC_PAD', 
    0x00000320 : 'CKM_CAST5_KEY_GEN', 
    0x00000320 : 'CKM_CAST128_KEY_GEN', 
    0x00000321 : 'CKM_CAST5_ECB', 
    0x00000321 : 'CKM_CAST128_ECB', 
    0x00000322 : 'CKM_CAST5_CBC', 
    0x00000322 : 'CKM_CAST128_CBC', 
    0x00000323 : 'CKM_CAST5_MAC', 
    0x00000323 : 'CKM_CAST128_MAC', 
    0x00000324 : 'CKM_CAST5_MAC_GENERAL', 
    0x00000324 : 'CKM_CAST128_MAC_GENERAL', 
    0x00000325 : 'CKM_CAST5_CBC_PAD', 
    0x00000325 : 'CKM_CAST128_CBC_PAD', 
    0x00000330 : 'CKM_RC5_KEY_GEN', 
    0x00000331 : 'CKM_RC5_ECB', 
    0x00000332 : 'CKM_RC5_CBC', 
    0x00000333 : 'CKM_RC5_MAC', 
    0x00000334 : 'CKM_RC5_MAC_GENERAL', 
    0x00000335 : 'CKM_RC5_CBC_PAD', 
    0x00000340 : 'CKM_IDEA_KEY_GEN', 
    0x00000341 : 'CKM_IDEA_ECB', 
    0x00000342 : 'CKM_IDEA_CBC', 
    0x00000343 : 'CKM_IDEA_MAC', 
    0x00000344 : 'CKM_IDEA_MAC_GENERAL', 
    0x00000345 : 'CKM_IDEA_CBC_PAD', 
    0x00000350 : 'CKM_GENERIC_SECRET_KEY_GEN', 
    0x00000360 : 'CKM_CONCATENATE_BASE_AND_KEY', 
    0x00000362 : 'CKM_CONCATENATE_BASE_AND_DATA', 
    0x00000363 : 'CKM_CONCATENATE_DATA_AND_BASE', 
    0x00000364 : 'CKM_XOR_BASE_AND_DATA', 
    0x00000365 : 'CKM_EXTRACT_KEY_FROM_KEY', 
    0x00000370 : 'CKM_SSL3_PRE_MASTER_KEY_GEN', 
    0x00000371 : 'CKM_SSL3_MASTER_KEY_DERIVE', 
    0x00000372 : 'CKM_SSL3_KEY_AND_MAC_DERIVE', 
    0x00000373 : 'CKM_SSL3_MASTER_KEY_DERIVE_DH', 
    0x00000374 : 'CKM_TLS_PRE_MASTER_KEY_GEN', 
    0x00000375 : 'CKM_TLS_MASTER_KEY_DERIVE', 
    0x00000376 : 'CKM_TLS_KEY_AND_MAC_DERIVE', 
    0x00000377 : 'CKM_TLS_MASTER_KEY_DERIVE_DH', 
    0x00000378 : 'CKM_TLS_PRF', 
    0x00000380 : 'CKM_SSL3_MD5_MAC', 
    0x00000381 : 'CKM_SSL3_SHA1_MAC', 
    0x00000390 : 'CKM_MD5_KEY_DERIVATION', 
    0x00000391 : 'CKM_MD2_KEY_DERIVATION', 
    0x00000392 : 'CKM_SHA1_KEY_DERIVATION', 
    0x00000393 : 'CKM_SHA256_KEY_DERIVATION', 
    0x00000394 : 'CKM_SHA384_KEY_DERIVATION', 
    0x00000395 : 'CKM_SHA512_KEY_DERIVATION', 
    0x00000396 : 'CKM_SHA224_KEY_DERIVATION', 
    0x000003A0 : 'CKM_PBE_MD2_DES_CBC', 
    0x000003A1 : 'CKM_PBE_MD5_DES_CBC', 
    0x000003A2 : 'CKM_PBE_MD5_CAST_CBC', 
    0x000003A3 : 'CKM_PBE_MD5_CAST3_CBC', 
    0x000003A4 : 'CKM_PBE_MD5_CAST5_CBC', 
    0x000003A4 : 'CKM_PBE_MD5_CAST128_CBC', 
    0x000003A5 : 'CKM_PBE_SHA1_CAST5_CBC', 
    0x000003A5 : 'CKM_PBE_SHA1_CAST128_CBC', 
    0x000003A6 : 'CKM_PBE_SHA1_RC4_128', 
    0x000003A7 : 'CKM_PBE_SHA1_RC4_40', 
    0x000003A8 : 'CKM_PBE_SHA1_DES3_EDE_CBC', 
    0x000003A9 : 'CKM_PBE_SHA1_DES2_EDE_CBC', 
    0x000003AA : 'CKM_PBE_SHA1_RC2_128_CBC', 
    0x000003AB : 'CKM_PBE_SHA1_RC2_40_CBC', 
    0x000003B0 : 'CKM_PKCS5_PBKD2', 
    0x000003C0 : 'CKM_PBA_SHA1_WITH_SHA1_HMAC', 
    0x000003D0 : 'CKM_WTLS_PRE_MASTER_KEY_GEN', 
    0x000003D1 : 'CKM_WTLS_MASTER_KEY_DERIVE', 
    0x000003D2 : 'CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC', 
    0x000003D3 : 'CKM_WTLS_PRF', 
    0x000003D4 : 'CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE', 
    0x000003D5 : 'CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE', 
    0x00000400 : 'CKM_KEY_WRAP_LYNKS', 
    0x00000401 : 'CKM_KEY_WRAP_SET_OAEP', 
    0x00000500 : 'CKM_CMS_SIG', 
    0x00000510 : 'CKM_KIP_DERIVE', 
    0x00000511 : 'CKM_KIP_WRAP', 
    0x00000512 : 'CKM_KIP_MAC', 
    0x00000550 : 'CKM_CAMELLIA_KEY_GEN', 
    0x00000551 : 'CKM_CAMELLIA_ECB', 
    0x00000552 : 'CKM_CAMELLIA_CBC', 
    0x00000553 : 'CKM_CAMELLIA_MAC', 
    0x00000554 : 'CKM_CAMELLIA_MAC_GENERAL', 
    0x00000555 : 'CKM_CAMELLIA_CBC_PAD', 
    0x00000556 : 'CKM_CAMELLIA_ECB_ENCRYPT_DATA', 
    0x00000557 : 'CKM_CAMELLIA_CBC_ENCRYPT_DATA', 
    0x00000558 : 'CKM_CAMELLIA_CTR', 
    0x00000560 : 'CKM_ARIA_KEY_GEN', 
    0x00000561 : 'CKM_ARIA_ECB', 
    0x00000562 : 'CKM_ARIA_CBC', 
    0x00000563 : 'CKM_ARIA_MAC', 
    0x00000564 : 'CKM_ARIA_MAC_GENERAL', 
    0x00000565 : 'CKM_ARIA_CBC_PAD', 
    0x00000566 : 'CKM_ARIA_ECB_ENCRYPT_DATA', 
    0x00000567 : 'CKM_ARIA_CBC_ENCRYPT_DATA', 
    0x00001000 : 'CKM_SKIPJACK_KEY_GEN', 
    0x00001001 : 'CKM_SKIPJACK_ECB64', 
    0x00001002 : 'CKM_SKIPJACK_CBC64', 
    0x00001003 : 'CKM_SKIPJACK_OFB64', 
    0x00001004 : 'CKM_SKIPJACK_CFB64', 
    0x00001005 : 'CKM_SKIPJACK_CFB32', 
    0x00001006 : 'CKM_SKIPJACK_CFB16', 
    0x00001007 : 'CKM_SKIPJACK_CFB8', 
    0x00001008 : 'CKM_SKIPJACK_WRAP', 
    0x00001009 : 'CKM_SKIPJACK_PRIVATE_WRAP', 
    0x0000100a : 'CKM_SKIPJACK_RELAYX', 
    0x00001010 : 'CKM_KEA_KEY_PAIR_GEN', 
    0x00001011 : 'CKM_KEA_KEY_DERIVE', 
    0x00001020 : 'CKM_FORTEZZA_TIMESTAMP', 
    0x00001030 : 'CKM_BATON_KEY_GEN', 
    0x00001031 : 'CKM_BATON_ECB128', 
    0x00001032 : 'CKM_BATON_ECB96', 
    0x00001033 : 'CKM_BATON_CBC128',
    0x00001034 : 'CKM_BATON_COUNTER', 
    0x00001035 : 'CKM_BATON_SHUFFLE', 
    0x00001036 : 'CKM_BATON_WRAP', 
    0x00001040 : 'CKM_ECDSA_KEY_PAIR_GEN', 
    0x00001040 : 'CKM_EC_KEY_PAIR_GEN', 
    0x00001041 : 'CKM_ECDSA', 
    0x00001042 : 'CKM_ECDSA_SHA1', 
    0x00001080 : 'CKM_AES_KEY_GEN', 
    0x00001081 : 'CKM_AES_ECB', 
    0x00001082 : 'CKM_AES_CBC', 
    0x00001083 : 'CKM_AES_MAC', 
    0x00001084 : 'CKM_AES_MAC_GENERAL', 
    0x00001085 : 'CKM_AES_CBC_PAD', 
    0x00001086 : 'CKM_AES_CTR', 
    0x00001090 : 'CKM_BLOWFISH_KEY_GEN', 
    0x00001091 : 'CKM_BLOWFISH_CBC', 
    0x00001092 : 'CKM_TWOFISH_KEY_GEN', 
    0x00001093 : 'CKM_TWOFISH_CBC', 
    0x00001100 : 'CKM_DES_ECB_ENCRYPT_DATA', 
    0x00001101 : 'CKM_DES_CBC_ENCRYPT_DATA', 
    0x00001102 : 'CKM_DES3_ECB_ENCRYPT_DATA', 
    0x00001103 : 'CKM_DES3_CBC_ENCRYPT_DATA', 
    0x00001104 : 'CKM_AES_ECB_ENCRYPT_DATA', 
    0x00001105 : 'CKM_AES_CBC_ENCRYPT_DATA', 
    0x00002000 : 'CKM_DSA_PARAMETER_GEN', 
    0x00002001 : 'CKM_DH_PKCS_PARAMETER_GEN', 
    0x00002002 : 'CKM_X9_42_DH_PARAMETER_GEN', 
    0x80000000 : 'CKM_VENDOR_DEFINED',
    0x00001200 : 'CKM_GOSTR3410_KEY_PAIR_GEN', 
    0x00001201 : 'CKM_GOSTR3410', 
    0x00001202 : 'CKM_GOSTR3410_WITH_GOSTR3411', 
    0x00001203 : 'CKM_GOSTR3410_KEY_WRAP', 
    0x00001204 : 'CKM_GOSTR3410_DERIVE', 
    0x00001210 : 'CKM_GOSTR3411', 
    0x00001211 : 'CKM_GOSTR3411_HMAC', 
    0x00001220 : 'CKM_GOST28147_KEY_GEN', 
    0x00001221 : 'CKM_GOST28147_ECB', 
    0x00001222 : 'CKM_GOST28147', 
    0x00001223 : 'CKM_GOST28147_MAC', 
    0x00001224 : 'CKM_GOST28147_KEY_WRAP',
    0xD4321005 : 'CKM_GOSTR3410_512_KEY_PAIR_GEN', 
    0xD4321006 : 'CKM_GOSTR3410_512', 
    0xD4321007 : 'CKM_GOSTR3410_12_DERIVE', 
    0xD4321008 : 'CKM_GOSTR3410_WITH_GOSTR3411_12_256', 
    0xD4321009 : 'CKM_GOSTR3410_WITH_GOSTR3411_12_512', 
    0xD4321012 : 'CKM_GOSTR3411_12_256', 
    0xD4321013 : 'CKM_GOSTR3411_12_512', 
    0xD4321014 : 'CKM_GOSTR3411_12_256_HMAC', 
    0xD4321015 : 'CKM_GOSTR3411_12_512_HMAC', 
    0xD4321025 : 'CKM_KDF_4357', 
    0xD4321026 : 'CKM_KDF_GOSTR3411_2012_256',
    0xD432102A : 'CKM_MAGMA_KEY_GEN',
    0xD4321028 : 'CKM_KUZNYECHIK_KEY_WRAP' #https://habr.com/ru/post/542182/
    }

#str2mech = {}
#for k,v in mech2str.items():
#    str2mech.setdefault(v,[]).append(k)
str2mech = { v:k for k,v in mech2str.items()}

mechFlag2str = {
           0x1 : 'CKF_HW', 
         0x100 : 'CKF_ENCRYPT', 
         0x200 : 'CKF_DECRYPT', 
         0x400 : 'CKF_DIGEST', 
         0x800 : 'CKF_SIGN', 
        0x1000 : 'CKF_SIGN_RECOVER', 
        0x2000 : 'CKF_VERIFY', 
        0x4000 : 'CKF_VERIFY_RECOVER', 
        0x8000 : 'CKF_GENERATE', 
       0x10000 : 'CKF_GENERATE_KEY_PAIR', 
       0x20000 : 'CKF_WRAP', 
       0x40000 : 'CKF_UNWRAP', 
       0x80000 : 'CKF_DERIVE', 
      0x100000 : 'CKF_EC_F_P', 
      0x200000 : 'CKF_EC_F_2M', 
      0x400000 : 'CKF_EC_ECPARAMETERS', 
      0x800000 : 'CKF_EC_NAMEDCURVE', 
     0x1000000 : 'CKF_EC_UNCOMPRESS', 
     0x2000000 : 'CKF_EC_COMPRESS', 
    0x80000000 : 'CKF_EXTENSION'
    }

str2initFlag = {
    'CKF_LIBRARY_CANT_CREATE_OS_THREADS' : 0x00000001,
    'CKF_OS_LOCKING_OK'                  : 0x00000002
}

str2sessonFlag = {
   'CKF_RW_SESSION'     : 0x00000002,
   'CKF_SERIAL_SESSION' : 0x00000004
}

str2tokenFlag = {
   'TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN'  : 0x00000001,
   'TOKEN_FLAGS_USER_CHANGE_USER_PIN'   : 0x00000002,
   'TOKEN_FLAGS_ADMIN_PIN_NOT_DEFAULT'  : 0x00000004,
   'TOKEN_FLAGS_USER_PIN_NOT_DEFAULT'   : 0x00000008,
   'TOKEN_FLAGS_SUPPORT_FKN'            : 0x00000010
}

ckaS2UL = {
    'CKA_CLASS'            : 0x00000000,
    'CKA_TOKEN'            : 0x00000001,
    'CKA_PRIVATE'          : 0x00000002,
    'CKA_LABEL'            : 0x00000003,
    'CKA_ID'               : 0x00000102,
    'CKA_KEY_TYPE'         : 0x00000100,
    'CKA_ENCRYPT'          : 0x00000104,
    'CKA_DECRYPT'          : 0x00000105,
    'CKA_GOSTR3410_PARAMS' : 0x00000250,
    'CKA_GOSTR3411_PARAMS' : 0x00000251,
    'CKA_GOST28147_PARAMS' : 0x00000252,
}

cko2UL = {
    "CKO_DATA "            : 0x00000000,
    "CKO_CERTIFICATE"      : 0x00000001,
    "CKO_PUBLIC_KEY"       : 0x00000002,
    "CKO_PRIVATE_KEY"      : 0x00000003,
    "CKO_SECRET_KEY"       : 0x00000004,
    "CKO_HW_FEATURE"       : 0x00000005,
    "CKO_DOMAIN_PARAMETERS": 0x00000006,
    "CKO_MECHANISM"        : 0x00000007,
    "CKO_OTP_KEY"          : 0x00000008,
    "CKO_VENDOR_DEFINED"   : 0x80000000
}

ckk2UL = {
    "CKK_GOSTR3410": 0x00000030,
    "CKK_GOSTR3411": 0x00000031,
    "CKK_GOST28147": 0x00000032
}

cdef CK_BBOOL CK_TRUE = 1
cdef CK_BBOOL CK_FALSE = 0
def dumpBuf(uintBufPtr: int, bufSz: int):

    printf("dump buf sz=%d\n",<uintptr_t> bufSz)

    cdef unsigned char * buf = <unsigned char *> <uintptr_t> uintBufPtr;
    for i in range(bufSz):
        printf(" 0x%02x", buf[i])
        if (i%8 == 7):
            printf("\n")
    printf("\n")


cdef CK_BYTE_PTR bytesToCharPtr(bytes bts):
    bts_len = len(bts)
    bts_sz = bts_len * sizeof(CK_BYTE)
    cdef CK_BYTE_PTR bts_uchar_ptr = <CK_BYTE_PTR> malloc(bts_sz)
    memcpy(bts_uchar_ptr, PyBytes_AsString(bts), bts_len )
#    print(0, chr(bts_uchar_ptr[0]))
#    print(1, chr(bts_uchar_ptr[1]))
    return bts_uchar_ptr

cdef CK_OBJECT_CLASS ocSecKey        = cko2UL['CKO_SECRET_KEY']
dumpBuf(<uintptr_t>&ocSecKey, sizeof(ocSecKey))

SecKeyLabel = b"GOST Secret Key"
cdef CK_UTF8CHAR* SecKeyLabel_uchar_ptr = bytesToCharPtr(SecKeyLabel)
dumpBuf(<uintptr_t>SecKeyLabel_uchar_ptr, len(SecKeyLabel)+1)

SecKeyID = b"GOST Secret Key"
cdef CK_BYTE_PTR SecKeyID_uchar_ptr = bytesToCharPtr(SecKeyID)
dumpBuf(<uintptr_t>SecKeyID_uchar_ptr, len(SecKeyID)+1)

cdef CK_KEY_TYPE     KeyType    = ckk2UL['CKK_GOST28147']
dumpBuf(<uintptr_t>&KeyType, sizeof(KeyType))
cdef CK_BBOOL        bTrue           = CK_TRUE
dumpBuf(<uintptr_t> &bTrue, sizeof(bTrue))
cdef CK_BBOOL        bFalse          = CK_FALSE
dumpBuf(<uintptr_t> &bFalse, sizeof(bFalse))
#/* Набор параметров КриптоПро A алгоритма ГОСТ 28147-89 */
GOST28147params = [ 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01 ]
print(len(GOST28147params))
cdef CK_BYTE_PTR     GOST28147params_uchar_ptr = <CK_BYTE_PTR> malloc(len(GOST28147params)*sizeof(CK_BYTE))
for i in range(len(GOST28147params)):
    GOST28147params_uchar_ptr[i] = GOST28147params[i]
dumpBuf(<uintptr_t> GOST28147params_uchar_ptr, len(GOST28147params))

cdef struct CK_ATTRIBUTE_LOC:
    CK_ATTRIBUTE_TYPE type
    CK_VOID_PTR pValue
    CK_ULONG ulValueLen

#<CK_ATTRIBUTE> CK_ATTRIBUTE(ckaS2UL['CKA_CLASS'], <CK_OBJECT_CLASS*> &ocSecKey, sizeof(ocSecKey))

cdef CK_ATTRIBUTE attrGOST28147_89SecKey[9]

attrGOST28147_89SecKey[0] = CK_ATTRIBUTE(ckaS2UL['CKA_CLASS'], &ocSecKey, sizeof(ocSecKey))
attrGOST28147_89SecKey[1] = CK_ATTRIBUTE(ckaS2UL['CKA_LABEL'], SecKeyLabel_uchar_ptr, len(SecKeyLabel))
attrGOST28147_89SecKey[2] = CK_ATTRIBUTE(ckaS2UL['CKA_ID'], SecKeyID_uchar_ptr, len(SecKeyID))
attrGOST28147_89SecKey[3] = CK_ATTRIBUTE(ckaS2UL['CKA_KEY_TYPE'], &KeyType, sizeof(KeyType))
attrGOST28147_89SecKey[4] = CK_ATTRIBUTE(ckaS2UL['CKA_ENCRYPT'], &bTrue, sizeof(bTrue))
attrGOST28147_89SecKey[5] = CK_ATTRIBUTE(ckaS2UL['CKA_DECRYPT'], &bTrue, sizeof(bTrue))
attrGOST28147_89SecKey[6] = CK_ATTRIBUTE(ckaS2UL['CKA_TOKEN'], &bFalse, sizeof(bFalse))
attrGOST28147_89SecKey[7] = CK_ATTRIBUTE(ckaS2UL['CKA_PRIVATE'], &bFalse, sizeof(bFalse))
attrGOST28147_89SecKey[8] = CK_ATTRIBUTE(ckaS2UL['CKA_GOST28147_PARAMS'], GOST28147params_uchar_ptr, len(GOST28147params))

dumpBuf(<uintptr_t>attrGOST28147_89SecKey[0].pValue, attrGOST28147_89SecKey[0].ulValueLen)
dumpBuf(<uintptr_t>attrGOST28147_89SecKey[1].pValue, attrGOST28147_89SecKey[1].ulValueLen)
dumpBuf(<uintptr_t>attrGOST28147_89SecKey[8].pValue, attrGOST28147_89SecKey[8].ulValueLen)

class Pkcs11Connection:

########################### INIT #####################################
    def __init__(self, path):

        print("Entering init_pkcs11")

        bpath = bytearray(path, 'utf-8')
        cdef void * module = dlopen(bpath, RTLD_NOW)
        print("Path=", path, " Module=", <uintptr_t>module)
        if <uintptr_t>module == 0:
          raise Pkcs11Exception(f"Error loading token pkcs11 dynamic librarry, dlerror= {dlerror()}")

        C_GetFunctionList_ba = bytearray("C_GetFunctionList",'utf-8')
        cdef CK_C_GetFunctionList getFunctionList
        getFunctionList = <CK_C_GetFunctionList> dlsym(module, C_GetFunctionList_ba)
        print("getFunctionList= ", <uintptr_t>getFunctionList)

        C_EX_GetFunctionListExtended_ba = bytearray("C_EX_GetFunctionListExtended",'utf-8')
        cdef CK_C_EX_GetFunctionListExtended getFunctionListEx
        getFunctionListEx = <CK_C_EX_GetFunctionListExtended> dlsym(module, C_EX_GetFunctionListExtended_ba)
        print("getFunctionListEx= ", <uintptr_t>getFunctionListEx)

        cdef CK_FUNCTION_LIST_PTR functionListI
        cdef CK_FUNCTION_LIST_EXTENDED_PTR functionListExI

        cdef CK_RV rv
        rv = getFunctionList(&functionListI)
        if rv != 0:
            raise Pkcs11Exception(f"getFunctionList: {hex(rv)}:{rv2str[rv]}")

        rv = getFunctionListEx(&functionListExI)
        if rv != 0:
            raise Pkcs11Exception(f"getFunctionListEx: {hex(rv)}:{rv2str[rv]}")

        cdef CK_C_INITIALIZE_ARGS initArgs

        initArgs = CK_C_INITIALIZE_ARGS(
                cython.NULL,
                cython.NULL,
                cython.NULL,
                cython.NULL,
                str2initFlag['CKF_OS_LOCKING_OK'],
                cython.NULL)

        rv = functionListI.C_Initialize(&initArgs)
        if rv != 0:
            raise Pkcs11Exception(f"C_Initialize: {hex(rv)}:{rv2str[rv]}")

        self.functionListUIP = <uintptr_t> functionListI
        self.functionListExUIP = <uintptr_t> functionListExI
        self.sessionUIP = <uintptr_t> cython.NULL

########################### FREE #####################################
    def free_pkcs11(self):

        cdef CK_FUNCTION_LIST_PTR functionListI = <CK_FUNCTION_LIST_PTR> <uintptr_t> self.functionListUIP
        cdef CK_RV rv

        rv = functionListI.C_Finalize(cython.NULL)

        if rv != 0:
            raise Pkcs11Exception(f"C_Finalize: {hex(rv)}:{rv2str[rv]}")

        print("free_pkcs11: Finish")

########################### LIST SLOTS #####################################
    def fill_slots_list(self):

        cdef CK_FUNCTION_LIST_PTR functionListI = <CK_FUNCTION_LIST_PTR><uintptr_t> self.functionListUIP

        cdef CK_SLOT_ID_PTR slotsI

        cdef CK_ULONG slotCount
        #cdef CK_ULONG_PTR slotCountPtr = &slotCount


        cdef CK_RV rv

        (&slotCount)[0]=12345

        #print(f"slotCount = 12345 = {slotCount:d}")

        rv =  functionListI.C_GetSlotList(1, cython.NULL, &slotCount)
        if rv != 0:
            raise Pkcs11Exception(f"C_GetSlotList: {hex(rv)}:{rv2str[rv]}")

        #print(f"slotCount= {slotCount:d}")

        self.slots=[]
        if <CK_ULONG>slotCount == 0:
            return

        slotsI = <CK_SLOT_ID_PTR> malloc(slotCount * sizeof(CK_SLOT_ID))

        rv =  functionListI.C_GetSlotList(1, slotsI, &slotCount)
        if rv != 0:
            raise Pkcs11Exception(f"C_GetSlotList: {hex(rv)}:{rv2str[rv]}")

        self.slots = [slotsI[i] for i in range(slotCount)]

        free(slotsI)

########################### LIST MECH #####################################
    def fill_mechanism_list(self):
        cdef CK_ULONG mechanismCount = 0

        if len(self.slots) == 0:
            return

        cdef CK_RV rv

        cdef CK_SLOT_ID slotID = self.slots[0]

        cdef CK_FUNCTION_LIST_PTR functionListI = <CK_FUNCTION_LIST_PTR><uintptr_t> self.functionListUIP

        # print(slotID)

        #cdef CK_SESSION_HANDLE session
        cdef CK_MECHANISM_TYPE_PTR mechanisms
        cdef CK_MECHANISM_INFO mechInfo

        #soPinBa = bytearray(str(pin),'utf-8')

        #rv = functionListI.C_OpenSession(slotID, 0x00000004 | 0x00000002, cython.NULL, cython.NULL, &session)
        #if rv != 0:
        #    raise Pkcs11Exception(f"C_OpenSession: {hex(rv)}")

        #rv = functionListI.C_Login(session, 1, soPinBa, len(soPinBa))
        #if rv != 0:
        #    raise Pkcs11Exception(f"C_Login: {hex(rv)}")

        rv = functionListI.C_GetMechanismList(slotID, cython.NULL, &mechanismCount)
        if rv != 0:
            raise Pkcs11Exception(f"C_GetMechanismList: {hex(rv)}")

        #print(f"mechanismCount= {mechanismCount:d}")

        mechanisms = <CK_MECHANISM_TYPE_PTR>malloc(mechanismCount * sizeof(CK_MECHANISM_TYPE))

        rv = functionListI.C_GetMechanismList(slotID, mechanisms, &mechanismCount)
        if rv != 0:
            raise Pkcs11Exception(f"C_GetMechanismList: {hex(rv)}")

        #rv = functionListI.C_GetMechanismInfo(slotID, mechanisms[13] , &mechInfo) #CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo
        #if rv != 0:
        #    raise Pkcs11Exception(f"C_GetMechanismInfo: {hex(rv)}")
        #i = 0

        self.mechanismCount = 0

        self.mechanisms = []

        i = 0

        while i < <int>mechanismCount:

            rv = functionListI.C_GetMechanismInfo(slotID, mechanisms[i] , &mechInfo)
            if rv != 0:
                raise Pkcs11Exception(f"C_GetMechanismInfo(mechanism {i}): {hex(rv)}")

            #print(f" {i}: mechanisms: {mech2string[mechanisms[i]]}, keySize= ({mechInfo.ulMinKeySize},{mechInfo.ulMaxKeySize}), mechInfo= {mechInfo.flags}", end=" ")

            n = mechInfo.flags
            l = len(re.sub('^0b','',bin(n)))
            listFlag = []

            for bn in range(0,l):
                b = 1 << bn
                bhs = f"0x{b:x}"
                #print(f"l:{l} bn:{bn:4d}   b:{b:8d}     bhs:{bhs:>8}")
                if n & b:
                    #print(f"n:{n}, b:{b}")
                    listFlag.append(mechFlag2str[b])
                    #print(mechFlag[bFlag] , end=" ")
            #print(listFlag)

            self.mechanisms.append(f"mechanism #{i:02d} {mech2str[mechanisms[i]]} keySize= {mechInfo.ulMinKeySize}, {mechInfo.ulMaxKeySize} {' '.join(listFlag)}")
            # print(" ")
            i+=1
        self.mechanismCount = i

########################### FORMAT TOKEN #####################################
    def format_token(self, soPin, pin, label):

        cdef CK_FUNCTION_LIST_EXTENDED_PTR functionListExI = <CK_FUNCTION_LIST_EXTENDED_PTR><uintptr_t> self.functionListExUIP
        cdef CK_SLOT_ID slot = self.slots[0]


        #print("---" + int(slot))/home/reversin/pPro/cYthon

        soPinBa = bytearray("87654321",'utf-8')
        pinBa = bytearray("12345678",'utf-8')
        labelBa = bytearray("myrutoken",'utf-8')

        cdef CK_RUTOKEN_INIT_PARAM initParam

        cdef CK_RV rv1
        errorCode = 1


        initParam.ulSizeofThisStructure = sizeof(CK_RUTOKEN_INIT_PARAM)
        initParam.UseRepairMode = 0
        initParam.pNewAdminPin = soPinBa
        initParam.ulNewAdminPinLen = len(soPinBa)
        initParam.pNewUserPin = pinBa
        initParam.ulNewUserPinLen = len(pinBa)
        initParam.ulMinAdminPinLen = 6
        initParam.ulMinUserPinLen = 6
        initParam.ChangeUserPINPolicy = str2tokenFlag['TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN']
        # | str2tokenFlag['TOKEN_FLAGS_USER_CHANGE_USER_PIN']
        initParam.ulMaxAdminRetryCount = 10
        initParam.ulMaxUserRetryCount = 10
        initParam.pTokenLabel = labelBa
        initParam.ulLabelLen = len(labelBa)
        initParam.ulSmMode = 0


        rv1 = functionListExI.C_EX_InitToken(slot, soPinBa, len(soPinBa), &initParam)
        if rv1 != 0:
            raise Pkcs11Exception(f"C_EX_InitToken: {hex(rv1)}")

        printf("Token has been formatted successfully.\n")


    def open_session(self, slotIx):
        cdef CK_SESSION_HANDLE session
        cdef CK_RV rv

        cdef CK_FUNCTION_LIST_PTR functionListI = <CK_FUNCTION_LIST_PTR> <uintptr_t> self.functionListUIP

        rv = functionListI.C_OpenSession(self.slots[slotIx], str2sessonFlag['CKF_SERIAL_SESSION'] | str2sessonFlag['CKF_RW_SESSION'], cython.NULL, cython.NULL, &session)
        if rv != 0:
            raise Pkcs11Exception(f"C_OpenSession: {hex(rv)}")

        self.sessionUIP = <uintptr_t> session

    def login(self, pin):
        cdef CK_SESSION_HANDLE session = <CK_SESSION_HANDLE> <uintptr_t> self.sessionUIP
        cdef CK_FUNCTION_LIST_PTR functionListI = <CK_FUNCTION_LIST_PTR> <uintptr_t> self.functionListUIP
        cdef CK_RV rv

        soPinBa = bytearray(str(pin),'utf-8')

        rv = functionListI.C_Login(session, 1, soPinBa, len(soPinBa))
        if rv != 0:
            raise Pkcs11Exception(f"C_Login: {hex(rv)}")

    def gen_key_pair(self,
                     pin,
                     keyPairID,
                     keyType,
                     parametersR3410_2012_256,
                     parametersR3411_2012_256,
                     template): #, pkTemplate

        attribTypes = {
            0: 0x00000000,
            1: 0x00000102,
            2: 0x00000100,
            3: 0x00000001,
            4: 0x00000002,
            5: 0x00000250,
            6: 0x00000251
        }
        voidPTR = []
        vLen = []

        cdef CK_RV rv
        cdef CK_FUNCTION_LIST_PTR functionListI = <CK_FUNCTION_LIST_PTR> <uintptr_t> self.functionListUIP
        cdef CK_SLOT_ID slotID = self.slots[0]
        cdef CK_SESSION_HANDLE session = <CK_SESSION_HANDLE> <uintptr_t> self.sessionUIP

        #soPin = bytearray(str(pin),'utf-8')

        #rv = functionListI.C_OpenSession(slotID, 0x00000004 | 0x00000002, cython.NULL, cython.NULL, &session)
        #if rv != 0:
        #    raise Pkcs11Exception(f"C_OpenSession: {hex(rv)}")

        #rv = self.functionListUIP.C_Login(session, 1, soPin, len(soPin))
        #if rv != 0:
        #    raise Pkcs11Exception(f"C_Login: {hex(rv)}")
        # temp1 = []
        #
        # # for i in range(len(template)):
        # #     print(f"temp {i}")
        # #     print(type(template[i].ret()[1]))
        # #     dumpBuf(<uintptr_t> template[i].ret()[1],template[i].ret()[2])
        # #     temp1.append(template[i].ret())
        #
        # print(temp1)



        cdef CK_OBJECT_CLASS publicKeyObject = cko2UL['CKO_PUBLIC_KEY']
        cdef CK_VOID_PTR toVoid = &publicKeyObject
        voidPTR[0] =  <uintptr_t>toVoid
        vLen[0] = sizeof(publicKeyObject)

        kPIGost2012_256 =  bytearray(str(keyPairID),'utf-8')
        cdef int kPIGost2012_256_len = len(kPIGost2012_256)
        cdef int kPIGost2012_256_sz = kPIGost2012_256_len * sizeof(CK_BYTE)

        cdef CK_BYTE * keyPairIdGost2012_256 = <CK_BYTE *> malloc(kPIGost2012_256_sz)
        for i in range(kPIGost2012_256_len):
            keyPairIdGost2012_256[i] = <CK_BYTE>kPIGost2012_256[i]

        voidPTR[1] = <uintptr_t>keyPairIdGost2012_256
        vLen[1] = kPIGost2012_256_sz

        cdef CK_KEY_TYPE keyTypeGostR3410_2012_256 = keyType
        cdef CK_VOID_PTR toVoidKey = &keyTypeGostR3410_2012_256
        voidPTR[2] =  <uintptr_t>toVoidKey
        vLen[2] = sizeof(keyTypeGostR3410_2012_256)

        cdef CK_BBOOL attributeTrue = 1
        cdef CK_VOID_PTR toVoidTrue = &attributeTrue
        voidPTR[3] = <uintptr_t>toVoidTrue
        vLen[3] = sizeof(attributeTrue)


        cdef CK_BBOOL attributeFalse = 0
        cdef CK_VOID_PTR toVoidFalse = &attributeFalse
        voidPTR[4] = <uintptr_t>toVoidFalse
        vLen[4] = sizeof(attributeFalse)


        pgR3410_2012_256 = parametersR3410_2012_256
        pgR3410_2012_256_len = len(pgR3410_2012_256)
        pgR3410_2012_256_sz = len(pgR3410_2012_256) * sizeof(CK_BYTE)
        cdef CK_BYTE * parametersGostR3410_2012_256 = <CK_BYTE *> malloc(pgR3410_2012_256_sz)
        for i in range(pgR3410_2012_256_len):
            parametersGostR3410_2012_256[i] = pgR3410_2012_256[i]

        voidPTR[5] = <uintptr_t>parametersGostR3410_2012_256
        vLen[5] = pgR3410_2012_256_sz

        pgR3411_2012_256 = parametersR3411_2012_256
        pgR3411_2012_256_len = len(pgR3411_2012_256)
        pgR3411_2012_256_sz = len(pgR3411_2012_256) * sizeof(CK_BYTE)

        cdef CK_BYTE * parametersGostR3411_2012_256 = <CK_BYTE *> malloc(pgR3411_2012_256_sz)
        for i in range(pgR3411_2012_256_len):
            parametersGostR3411_2012_256[i] = pgR3411_2012_256[i]
        voidPTR[6] = <uintptr_t>parametersGostR3411_2012_256
        vLen[6] = pgR3411_2012_256_sz

        pubLen = len(attribTypes)
        pbSZ = pubLen * sizeof(CK_ATTRIBUTE)

        cdef CK_ATTRIBUTE *publicKeyTemplate = <CK_ATTRIBUTE*> malloc(pbSZ)


        for i in range(pubLen):
            print(f"{i} : {<uintptr_t>&publicKeyTemplate[i]}")
            template[i].ret(<uintptr_t>&publicKeyTemplate[i])
            #        publicKeyTemplate[i].type = temp1[i][0]
            #        publicKeyTemplate[i].pValue = <CK_VOID_PTR><uintptr_t>temp1[i][1]
            #        publicKeyTemplate[i].ulValueLen  = temp1[i][2]
            print(<uintptr_t> publicKeyTemplate[i].pValue)
            dumpBuf(<uintptr_t> publicKeyTemplate[i].pValue, publicKeyTemplate[i].ulValueLen)


        cdef CK_OBJECT_CLASS privateKeyObject =cko2UL['CKO_PRIVATE_KEY']
        cdef CK_VOID_PTR toVoidPriv = &privateKeyObject
        voidPTR[0] = <uintptr_t> toVoidPriv
        vLen[0] = sizeof(privateKeyObject)

        voidPTR[4] = <uintptr_t>toVoidTrue
        vLen[4] = sizeof(attributeTrue)

        privLen = len(attribTypes)
        privSize = len(attribTypes) * sizeof(CK_ATTRIBUTE)
        cdef CK_ATTRIBUTE *privateKeyTemplate = <CK_ATTRIBUTE *> malloc(privSize)

        for i in range(privLen):
            privateKeyTemplate[i].type = attribTypes[i]
            privateKeyTemplate[i].pValue = <CK_VOID_PTR><uintptr_t>voidPTR[i]
            privateKeyTemplate[i].ulValueLen  = vLen[i]


        cdef CK_OBJECT_HANDLE privateKey
        cdef CK_OBJECT_HANDLE publicKey


        cdef CK_MECHANISM gostR3410_2012_256KeyPairGenMech
        gostR3410_2012_256KeyPairGenMech = CK_MECHANISM(str2mech['CKM_GOSTR3410_KEY_PAIR_GEN'], cython.NULL, 0)


        # for i in range(len(attribTypes)):
        #     print(f"pubType {i}: {publicKeyTemplate[i].type} | temp1 {i}: {temp1[i][0]} | privType {i}: {privateKeyTemplate[i].type}")
        #     print(f"pubValue {i}: {<uintptr_t>publicKeyTemplate[i].pValue} | temp1 {i}: {temp1[i][1]} privValue {i}: {<uintptr_t>privateKeyTemplate[i].pValue}")
        #     print(f"pubValueLen {i}: {publicKeyTemplate[i].ulValueLen} | temp1 {i}: {temp1[i][2]} privValueLen {i}: {privateKeyTemplate[i].ulValueLen}")
        #     print(" ")



        rv = functionListI.C_GenerateKeyPair(session, &gostR3410_2012_256KeyPairGenMech,
                                             publicKeyTemplate, pubLen,
                                             privateKeyTemplate, privLen,
                                             &publicKey, &privateKey)
        print(f"publicKey= {publicKey}")
        print(f"privateKey= {privateKey}")

        if rv != 0:
            raise Pkcs11Exception(f"C_GenerateKeyPair: {rv2str[rv]}")

        print("Gost key pair generated sucessfully\n")
        return 0
    def gen_key_symm(self):
        cdef CK_MECHANISM keyGenMech = CK_MECHANISM(str2mech['CKM_GOST28147_KEY_GEN'], cython.NULL, 0)
        cdef CK_OBJECT_HANDLE hSecKey = <CK_OBJECT_HANDLE> cython.NULL
        cdef CK_FUNCTION_LIST_PTR functionListI = <CK_FUNCTION_LIST_PTR> <uintptr_t> self.functionListUIP
        cdef CK_SLOT_ID slotID = self.slots[0]
        cdef CK_SESSION_HANDLE session = <CK_SESSION_HANDLE> <uintptr_t> self.sessionUIP
        cdef CK_RV rv

        cdef CK_ULONG array_sz = sizeof(attrGOST28147_89SecKey)
        cdef CK_ULONG elem_sz = sizeof(attrGOST28147_89SecKey[0])
        cdef CK_ULONG elem_num = array_sz // elem_sz

        printf("sizeof secretKeyAttribs: %d %d %d\n", array_sz, elem_sz, elem_num)

        dumpBuf(<uintptr_t>&keyGenMech,sizeof(keyGenMech))
        dumpBuf(<uintptr_t>attrGOST28147_89SecKey, 216)

        rv = functionListI.C_GenerateKey(session,
                                         &keyGenMech,
                                         attrGOST28147_89SecKey,
                                         elem_num,
                                         &hSecKey
                                         )
        if rv != 0:
            raise Pkcs11Exception(f"C_GenerateKey: {hex(rv)} : {rv2str[rv]}")

        print("28147 key generated sucessfully\n")



#/* Вычисление размера массива */
##define          arraysize(a)   (sizeof(a)/sizeof(a[0]))
#
#CK_MECHANISM     KeyGenMech  = {CKM_GOST28147_KEY_GEN, NULL_PTR, 0}; // Генерация ключа ГОСТ 28147-89. Для генерации секретных ключей Кузнечик и Магма нужно использовать механизмы CKM_KUZNECHIK_KEY_GEN и CKM_MAGMA_KEY_GEN
#
#CK_OBJECT_HANDLE hSecKey     = NULL_PTR;                            // Хэндл cекретного ключа
#
#...
#printf("\n Generating key");
#rv = pFunctionList->C_GenerateKey(hSession,                             // Хэндл открытой сессии
#                                  &KeyGenMech,                          // Используемый механизм генерации ключа
#                                  attrGOST28147_89SecKey,               // Шаблон для создания секретного ключа
#                                  arraysize(attrGOST28147_89SecKey),    // Размер шаблона секретного ключа
#                                  &hSecKey);                            // Хэндл секретного ключа
#if (rv != CKR_OK)
#    printf(" -> Failed\n");
#else
#    printf(" -> OK\n");
#




# class CK_ATTRIB:
#     def retPtr(self):
#         return <uintptr_t> ck_attrib_ptr
#     def retData(self):
#         return ck_attrib.type, (<CK_ULONG *> ck_attrib.pValue)[0], ck_attrib.ulValueLen

cdef class CKA_CLASS:
    cdef int Att
    def __init__(self,Att):
        self.Att = Att

    def ret(self, template_atr_ptr ):
        cdef CK_OBJECT_CLASS publicKeyObject = self.Att

        cdef CK_VOID_PTR pubToVoid = &publicKeyObject

        print("CKA_CLASS ret:", <uintptr_t>template_atr_ptr)
        cdef CK_ATTRIBUTE *pkTemplate = <CK_ATTRIBUTE *><uintptr_t>template_atr_ptr
        pkTemplate.type = ckaS2UL['CKA_CLASS']
        pkTemplate.pValue = pubToVoid
        pkTemplate.ulValueLen  = sizeof(publicKeyObject)

        print(<uintptr_t>pkTemplate.pValue)
        dumpBuf(<uintptr_t> pkTemplate.pValue, pkTemplate.ulValueLen)
    def retAtt(self):
        return self.Att


class CKA_ID:
    def __init__(self,attribute):
        self.attribute = attribute

    def ret(self):

        kPIGost2012_256 = bytearray(str(self.attribute), 'utf-8')
        cdef int kPIGost2012_256_len = len(kPIGost2012_256)
        cdef int kPIGost2012_256_sz = kPIGost2012_256_len * sizeof(CK_BYTE)

        cdef CK_BYTE * keyPairIdGost2012_256 = <CK_BYTE *> malloc(kPIGost2012_256_sz)
        for i in range(kPIGost2012_256_len):
            keyPairIdGost2012_256[i] = <CK_BYTE> kPIGost2012_256[i]

        return ckaS2UL['CKA_ID'],<uintptr_t> keyPairIdGost2012_256, kPIGost2012_256_sz

class CKA_KEY_TYPE:
    def __init__(self,attribute):
        self.attribute = attribute

    def ret(self):
        cdef CK_KEY_TYPE keyTypeGostR3410_2012_256 = self.attribute
        cdef CK_VOID_PTR toVoidKey = &keyTypeGostR3410_2012_256
        return ckaS2UL['CKA_KEY_TYPE'], <uintptr_t>toVoidKey, sizeof(keyTypeGostR3410_2012_256)

class CKA_TOKEN:
    def __init__(self, attribute):
        self.attribute = attribute

    def ret(self):
        cdef CK_BBOOL attributeTrue = 1
        cdef CK_VOID_PTR toVoidTrue = &attributeTrue
        return ckaS2UL['CKA_TOKEN'], <uintptr_t>toVoidTrue, sizeof(attributeTrue)

class CKA_PRIVATE:
    def __init__(self, Att):
        self.Att = Att


    def ret(self):
        cdef CK_BBOOL attribute = self.Att
        cdef CK_VOID_PTR toVoid= &attribute

        return ckaS2UL['CKA_PRIVATE'], <uintptr_t>toVoid, sizeof(attribute)

class CKA_GOSTR3410_PARAMS:
    def __init__(self, attribute):
        self.attribute = attribute

    def ret(self):

        pgR3410_2012_256 = self.attribute.split()
        pgR3410_2012_256_len = len(pgR3410_2012_256)
        pgR3410_2012_256_sz = len(pgR3410_2012_256) * sizeof(CK_BYTE)

        cdef CK_BYTE * parametersGostR3410_2012_256 = <CK_BYTE *> malloc(pgR3410_2012_256_sz)
        for i in range(pgR3410_2012_256_len):

            parametersGostR3410_2012_256[i] = int(pgR3410_2012_256[i],16)

        return ckaS2UL['CKA_GOSTR3410_PARAMS'], <uintptr_t> parametersGostR3410_2012_256, pgR3410_2012_256_sz

class CKA_GOSTR3411_PARAMS:
    def __init__(self, attribute):
        self.attribute = attribute

    def ret(self):
        pgR3411_2012_256 = self.attribute.split()
        pgR3411_2012_256_len = len(pgR3411_2012_256)
        pgR3411_2012_256_sz = len(pgR3411_2012_256) * sizeof(CK_BYTE)

        cdef CK_BYTE * parametersGostR3411_2012_256 = <CK_BYTE *> malloc(pgR3411_2012_256_sz)
        for i in range(pgR3411_2012_256_len):
            parametersGostR3411_2012_256[i] = int(pgR3411_2012_256[i],16)

        return ckaS2UL['CKA_GOSTR3411_PARAMS'], <uintptr_t> parametersGostR3411_2012_256, pgR3411_2012_256_sz

class  GOST28147_TEMPLATE:
    def __init__(self,attribute):
        self.attribute = attribute
