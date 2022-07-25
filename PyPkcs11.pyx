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

    ctypedef unsigned char CK_BYTE
    ctypedef CK_BYTE CK_BBOOL
    ctypedef CK_BYTE CK_UTF8CHAR
    ctypedef CK_BYTE *CK_BYTE_PTR

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
    ctypedef CK_FUNCTION_LIST_PTR * CK_FUNCTION_LIST_EXTENDED_PTR_PTR
    ctypedef CK_RV ( * CK_C_EX_GetFunctionListExtended) ( CK_FUNCTION_LIST_EXTENDED_PTR_PTR ppFunctionList )
    ctypedef CK_RV ( * CK_C_EX_InitToken) ( CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_RUTOKEN_INIT_PARAM_PTR pInitInfo )

    ctypedef CK_ULONG CK_SLOT_ID


    ctypedef CK_RV ( * CK_CREATEMUTEX)  (CK_VOID_PTR_PTR)
    ctypedef CK_RV ( * CK_DESTROYMUTEX) (CK_VOID_PTR_PTR)
    ctypedef CK_RV ( * CK_LOCKMUTEX)    (CK_VOID_PTR_PTR)
    ctypedef CK_RV ( * CK_UNLOCKMUTEX)  (CK_VOID_PTR_PTR)

    ctypedef CK_ULONG CK_FLAGS

    struct CK_INFO:
        CK_VERSION    cryptokiVersion   
        CK_UTF8CHAR   manufacturerID[32]
        CK_FLAGS      flags              
        CK_UTF8CHAR   libraryDescription[32]
        CK_VERSION    libraryVersion  

    struct CK_FUNCTION_LIST:
        CK_VERSION version
        CK_C_Initialize C_Initialize
        CK_C_Finalize C_Finalize
        CK_C_GetInfo C_GetInfo
        CK_C_GetFunctionList C_GetFunctionList
        CK_C_GetSlotList C_GetSlotList

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
        CK_FLAGS    ChangeUserPINPolicy;
        CK_ULONG    ulMinAdminPinLen
        CK_ULONG    ulMinUserPinLen
        CK_ULONG    ulMaxAdminRetryCount
        CK_ULONG    ulMaxUserRetryCount
        CK_BYTE_PTR pTokenLabel
        CK_ULONG    ulLabelLen
        CK_ULONG    ulSmMode

cdef CK_FUNCTION_LIST_PTR functionList
cdef CK_FUNCTION_LIST_EXTENDED_PTR functionListEx
cdef CK_FUNCTION_LIST cfl

rvToStrDict = { 
    0: 'CKR_OK', 
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


    cdef CK_RV rv1
    rv1 = getFunctionList(&functionList)


    cdef CK_RV rv3
    rv3 = functionList.C_Initialize(&initArgs)

    
    return rv1,rv3

def free_pkcs11():
  
  cdef CK_RV rv1
  errorCode = 1

  rv = functionList.C_Finalize(cython.NULL)
  
  return errorCode

def get_slots_list():

  cdef CK_SLOT_ID_PTR slots
  cdef CK_SLOT_ID_PTR *slots_ptr = &slots

  cdef CK_ULONG slotCount
  cdef CK_ULONG_PTR slotCountPtr = &slotCount


  cdef CK_RV rv1

  slotCountPtr[0]=12345

  print(" Slots available: ", <CK_ULONG>slotCount)
  print("cython.NULL: ", <uintptr_t>cython.NULL)

  rv1 =  functionList.C_GetSlotList(1, cython.NULL, slotCountPtr)
  print("result: ", rvToString(rv1))

  print(" Slots available: ", <CK_ULONG>slotCount)



  slots_ptr[0] = <CK_SLOT_ID_PTR> malloc(slotCount * sizeof(CK_SLOT_ID))


  rv2 =  functionList.C_GetSlotList(1, slots_ptr[0], slotCountPtr)
  print(" C_GetSlotList: ", <CK_ULONG>rv2)

  return rv1, rv2

def format_token():
 
    
    cdef CK_SLOT_ID slot

    soPin = bytearray("87654321",'utf-8')
    pin = bytearray("12345678",'utf-8')
    
    cdef CK_RUTOKEN_INIT_PARAM initParam
    
    cdef CK_RV rv1
    errorCode = 1
    
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
    initParam.pTokenLabel = "rutoken"
    initParam.ulLabelLen = 7
    initParam.ulSmMode = 0


    rv1 = functionListEx.C_EX_InitToken(slot, soPin, len(soPin), &initParam)
    print("result: ", rvToString(rv1))
    
    errorCode = 0
    printf("Token has been initialized successfully.\n")

    return rv1





