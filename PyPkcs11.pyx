import cython

from libc.stdlib cimport malloc
from libc.stdio cimport printf

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

cdef CK_FUNCTION_LIST_PTR functionList
cdef CK_FUNCTION_LIST_EXTENDED_PTR functionListEx
cdef CK_FUNCTION_LIST cfl
cdef CK_SLOT_ID_PTR slots

rvToStrDict = { 
    0: 'CKR_OK', 
    1: 'CKR_CANCEL',
    2: 'CKR_HOST_MEMORY',
    3: 'CKR_SLOT_ID_INVALID',
    7: 'CKR_ARGUMENTS_BAD' 
        }

def rvToString(rv):
    return rvToStrDict[rv]


def init_pkcs11(path):

    print("Entering init_pkcs11")

    cdef CK_C_INITIALIZE_ARGS initArgs
    initArgs = CK_C_INITIALIZE_ARGS(
            cython.NULL,
            cython.NULL,
            cython.NULL,
            cython.NULL,
            0x00000002, 
            cython.NULL)

    bpath = bytearray(path, 'utf-8')
    cdef void * module = dlopen(bpath, RTLD_NOW)
    print("Path=", path, " Module=", <uintptr_t>module)
    if <uintptr_t>module == 0:
      print("dlerror= ",dlerror())

    C_GetFunctionList_ba = bytearray("C_GetFunctionList",'utf-8')
    cdef CK_C_GetFunctionList getFunctionList
    getFunctionList = <CK_C_GetFunctionList> dlsym(module, C_GetFunctionList_ba)
    print("getFunctionList= ", <uintptr_t>getFunctionList)

    C_EX_GetFunctionListExtended_ba = bytearray("C_EX_GetFunctionListExtended",'utf-8')
    cdef CK_C_EX_GetFunctionListExtended getFunctionListEx
    getFunctionListEx = <CK_C_EX_GetFunctionListExtended> dlsym(module, C_EX_GetFunctionListExtended_ba)
    print("getFunctionListEx= ", <uintptr_t>getFunctionListEx)

    cdef CK_RV rv1
    rv1 = getFunctionList(&functionList)

    cdef CK_RV rv2
    rv2 = getFunctionListEx(&functionListEx)

    cdef CK_RV rv3
    rv3 = functionList.C_Initialize(&initArgs)



    
    return rv1,rv3

def free_pkcs11():
  
  cdef CK_RV rv1
  errorCode = 1

  rv = functionList.C_Finalize(cython.NULL)
  
  return errorCode

def get_slots_list():

 
  cdef CK_SLOT_ID_PTR *slots_ptr = &slots

  cdef CK_ULONG slotCount
  cdef CK_ULONG_PTR slotCountPtr = &slotCount


  cdef CK_RV rv1

  slotCountPtr[0]=12345

  print(" Slots available: ", <CK_ULONG>slotCount)
  #print("cython.NULL: ", <uintptr_t>cython.NULL)

  rv1 =  functionList.C_GetSlotList(1, cython.NULL, slotCountPtr)
  print("result: ", rvToString(rv1))

  print(" Slots available: ", <CK_ULONG>slotCount)



  slots_ptr[0] = <CK_SLOT_ID_PTR> malloc(slotCount * sizeof(CK_SLOT_ID))


  rv2 =  functionList.C_GetSlotList(1, slots_ptr[0], slotCountPtr)
  #print(" C_GetSlotList: ", <CK_ULONG>rv2)

  return rv1, rv2

def format_token():
 
    cdef CK_SLOT_ID slot = slots[0]
    

    #print("---" + int(slot))

    soPin = bytearray("87654321",'utf-8')
    pin = bytearray("12345678",'utf-8')
    label = bytearray("rutoken",'utf-8')
    
    cdef CK_RUTOKEN_INIT_PARAM initParam
    
    cdef CK_RV rv1
    errorCode = 1

    
    initParam.ulSizeofThisStructure = sizeof(CK_RUTOKEN_INIT_PARAM)
    initParam.UseRepairMode = 0
    initParam.pNewAdminPin = soPin
    initParam.ulNewAdminPinLen = 8
    initParam.pNewUserPin = pin
    initParam.ulNewUserPinLen = 8
    initParam.ulMinAdminPinLen = 6
    initParam.ulMinUserPinLen = 6
    initParam.ChangeUserPINPolicy = (0x00000001 | 0x00000002)
    initParam.ulMaxAdminRetryCount = 10
    initParam.ulMaxUserRetryCount = 10
    initParam.pTokenLabel = label
    initParam.ulLabelLen = 7
    initParam.ulSmMode = 0


    rv1 = functionListEx.C_EX_InitToken(slot, soPin, len(soPin), &initParam)
    print("result: ", rvToString(rv1))
    
    errorCode = 0
    printf("Token has been initialized successfully.\n")

    return rv1

mech2string = {
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
    0x80000000 : 'CKM_VENDOR_DEFINED'
    }

def mechanism_list(pin):

    cdef CK_RV rv

    cdef CK_MECHANISM_TYPE mech = 0x00001220

    cdef CK_SLOT_ID slotID = slots[0]

    cdef CK_SESSION_HANDLE session
    cdef CK_ULONG mechanismCount
    cdef CK_MECHANISM_TYPE_PTR mechanisms

    soPin = bytearray(str(pin),'utf-8')

    rv = functionList.C_OpenSession(slotID, 0x00000004 | 0x00000002, cython.NULL, cython.NULL, &session)
    print("result 1: ", rvToString(rv))

    rv = functionList.C_Login(session, 1, soPin, len(soPin))

    print("result 2: ", rvToString(rv))
    
    print("slotID: ",slotID)
    print("mechanismCount: ",mechanismCount)

    rv = functionList.C_GetMechanismList(slotID, cython.NULL, &mechanismCount)


    mechanisms = <CK_MECHANISM_TYPE_PTR>malloc(mechanismCount * sizeof(CK_MECHANISM_TYPE))

    rv = functionList.C_GetMechanismList(slotID, mechanisms, &mechanismCount)

    i = 0
    while i < <int>mechanismCount:
        print(mechanisms[i])
        #print(" {}: mechanisms: {:x} {} ".format( i, mechanisms[i], mech2string[mechanisms[i]]))
        i+=1
        
    
    return rv


    


