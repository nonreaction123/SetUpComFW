//----------------------------------------------------------------------------
// CONFIDENTIAL
//
// COPYRIGHT RESERVED, 2020 Robert Bosch (Australia) Pty Ltd.
// All rights reserved.  The reproduction, distribution and utilisation of
// this document as well as the communication of its contents to others
// without explicit authorisation is prohibited.  Offenders will be held liable
// for the payment of damages.  All rights reserved in the event of the grant
// of a patent, utility model or design.
//----------------------------------------------------------------------------

//----------------------------------------------------------------------------
//! \file capldll.cpp
//! \brief CAPL dll for CANoe
//!
//! Module Description
//!     The intended use of this dll is to be import from a CAPL script
//!     From the capl script SHA256 hashing could be done via this dll's interface
//!     From the capl script ECDSA (NISTP256) signing or verifying could be done via this dll's interface
//!
//----------------------------------------------------------------------------


#define USECDLL_FEATURE
#define _BUILDNODELAYERDLL


#include "..\Includes\cdll.h"
#include "..\Includes\via.h"
#include "..\Includes\via_CDLL.h"

#include <stdio.h>
#include <stdlib.h>
#include <map>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

static BCRYPT_ALG_HANDLE       hAlg = NULL;
static BCRYPT_HASH_HANDLE      hHash = NULL;
static NTSTATUS                status = STATUS_UNSUCCESSFUL;
static DWORD                   cbData = 0, cbHash = 0, cbHashObject = 0, cbSignature = 0;
static PBYTE                   pbHashObject = NULL, pbSignature = NULL;
static PBYTE                   pbHash = NULL;

static BCRYPT_ALG_HANDLE       hAlgKeyPair = NULL;
static BCRYPT_KEY_HANDLE	   hKeyPair = NULL;

static BCRYPT_ALG_HANDLE       hAlgPrivateKey = NULL;
static BCRYPT_KEY_HANDLE	   *hPrivateKey = NULL;
static BCRYPT_ALG_HANDLE       hAlgPublicKey = NULL;
static BCRYPT_KEY_HANDLE	   *hPublicKey = NULL;

static PBYTE                   KeyBlobPr = NULL;
static DWORD                   KeyBlobPrLength = 0;
static DWORD                   ResultPrLength = 0;

static PBYTE                   KeyBlobPu = NULL;
static DWORD                   KeyBlobPuLength = 0;
static DWORD                   ResultPuLength = 0;

class CaplInstanceData;
typedef std::map<uint32, CaplInstanceData*> VCaplMap;
typedef std::map<uint32, VIACapl*> VServiceMap;


// ============================================================================
// global variables
// ============================================================================

static unsigned long data = 0;
static char dlldata[100];

char        gModuleName[_MAX_FNAME];  // filename of this  dll 
HINSTANCE   gModuleHandle;            // windows instance handle of this DLL
VCaplMap    gCaplMap;   
VServiceMap gServiceMap;


// ============================================================================
// CaplInstanceData
// 
// Data local for a single CAPL Block. 
//
// A CAPL-DLL can be used by more than one CAPL-Block, so every piece of 
// information thats like a globale variable in CAPL, must now be wraped into 
// an instance of an object.
// ============================================================================
class CaplInstanceData
{
public:
  CaplInstanceData(VIACapl* capl);
  
  void GetCallbackFunctions();
  void ReleaseCallbackFunctions();

  // Definition of the class function. 
  // This class function will call the 
  // CAPL callback functions 
  uint32 ShowValue(uint32 x);
  uint32 ShowDates(int16 x, uint32 y, int16 z);
  void   DllInfo(char* x);
  void   ArrayValues(uint32 flags, uint32 numberOfDatabytes, uint8 databytes[], uint8 controlcode);
  void DllVersion(char* y);

private:  

  // Pointer of the CAPL callback functions 
  VIACaplFunction*  mShowValue;
  VIACaplFunction*  mShowDates;
  VIACaplFunction*  mDllInfo;
  VIACaplFunction*  mArrayValues;
  VIACaplFunction*  mDllVersion;

  VIACapl*          mCapl;
};


CaplInstanceData::CaplInstanceData(VIACapl* capl) 
  // This function will initialize the CAPL callback function 
  // with the NLL Pointer 
 : mCapl(capl), 
   mShowValue(NULL),
   mShowDates(NULL),
   mDllInfo(NULL),
   mArrayValues(NULL),
   mDllVersion(NULL)
{}

static bool sCheckParams(VIACaplFunction* f, char rtype, char* ptype)
{
  char      type;
  int32     pcount;
  VIAResult rc;

  // check return type
  rc = f->ResultType(&type);
  if (rc!=kVIA_OK || type!=rtype)
  {
    return false;
  }

  // check number of parameters
  rc = f->ParamCount(&pcount);
  if (rc!=kVIA_OK || strlen(ptype)!=pcount )
  {
    return false;
  }

  // check type of parameters
  for (int i=0; i<pcount; ++i)
  {
    rc = f->ParamType(&type, i);
    if (rc!=kVIA_OK || type!=ptype[i])
    {
      return false;
    }
  }

  return true;
}

static VIACaplFunction* sGetCaplFunc(VIACapl* capl, const char * fname, char rtype, char* ptype)
{
  VIACaplFunction* f; 

  // get capl function object
  VIAResult rc =  capl->GetCaplFunction(&f, fname);
  if (rc!=kVIA_OK || f==NULL) 
  {
    return NULL;
  }

  // check signature of function
  if ( sCheckParams(f, rtype, ptype) )
  {
     return f;
  }
  else
  {
    capl->ReleaseCaplFunction(f);
    return NULL;
  }
}

void CaplInstanceData::GetCallbackFunctions()
{
  // Get a CAPL function handle. The handle stays valid until end of
  // measurement or a call of ReleaseCaplFunction. 
  mShowValue   = sGetCaplFunc(mCapl, "CALLBACK_ShowValue", 'D', "D");
  mShowDates   = sGetCaplFunc(mCapl, "CALLBACK_ShowDates", 'D', "IDI");
  mDllInfo     = sGetCaplFunc(mCapl, "CALLBACK_DllInfo", 'V', "C");
  mArrayValues = sGetCaplFunc(mCapl, "CALLBACK_ArrayValues", 'V', "DBB");
  mDllVersion  = sGetCaplFunc(mCapl, "CALLBACK_DllVersion", 'V', "C");
}

void CaplInstanceData::ReleaseCallbackFunctions()
{
  // Release all the requested Callback functions 
  mCapl->ReleaseCaplFunction(mShowValue);
  mShowValue = NULL;
  mCapl->ReleaseCaplFunction(mShowDates);
  mShowDates = NULL;
  mCapl->ReleaseCaplFunction(mDllInfo);
  mDllInfo = NULL;
  mCapl->ReleaseCaplFunction(mArrayValues);
  mArrayValues = NULL;
  mCapl->ReleaseCaplFunction(mDllVersion);
  mDllVersion = NULL;
}

void CaplInstanceData::DllVersion(char* y)
{
  // Prepare the parameters for the call stack of CAPL. 
  // Arrays uses a 8 byte on the stack, 4 Bytes for the number of element,
  // and 4 bytes for the pointer to the array
  int32 sizeX = strlen(y)+1;

  uint8 params[8];               // parameters for call stack, 8 Bytes total    
  memcpy(params+0, &sizeX, 4);   // array size    of first parameter, 4 Bytes
  memcpy(params+4, &y,     4);   // array pointer of first parameter, 4 Bytes
  
  if(mDllVersion!=NULL)
  {
    uint32 result; // dummy variable
    VIAResult rc =  mDllVersion->Call(&result, params);
  }
}


uint32 CaplInstanceData::ShowValue(uint32 x)
{
  void* params = &x;   // parameters for call stack

  uint32 result;

  if(mShowValue!=NULL)
  {
    VIAResult rc =  mShowValue->Call(&result, params);
    if (rc==kVIA_OK)
    {
       return result;
    }
  }    
  return -1;
}

uint32 CaplInstanceData::ShowDates(int16 x, uint32 y, int16 z)
{
  // Prepare the parameters for the call stack of CAPL. The stack grows
  // from top to down, so the first parameter in the parameter list is the last 
  // one in memory. CAPL uses also a 32 bit alignment for the parameters. 
  uint8 params[12];         // parameters for call stack, 12 Bytes total    
  memcpy(params+0, &z, 2);  // third  parameter, offset 0, 2 Bytes
  memcpy(params+4, &y, 4);  // second parameter, offset 4, 4 Bytes
  memcpy(params+8, &x, 2);  // first  parameter, offset 8, 2 Bytes 

  uint32 result;

  if(mShowDates!=NULL)
  {
    VIAResult rc =  mShowDates->Call(&result, params);
    if (rc==kVIA_OK)
    {
       return rc;   // call successful
    }
  } 
    
  return -1; // call failed
}

void CaplInstanceData::DllInfo(char* x)
{
  // Prepare the parameters for the call stack of CAPL. 
  // Arrays uses a 8 byte on the stack, 4 Bytes for the number of element,
  // and 4 bytes for the pointer to the array
  int32 sizeX = strlen(x)+1;

  uint8 params[8];               // parameters for call stack, 8 Bytes total    
  memcpy(params+0, &sizeX, 4);   // array size    of first parameter, 4 Bytes
  memcpy(params+4, &x,     4);   // array pointer of first parameter, 4 Bytes
  
  if(mDllInfo!=NULL)
  {
    uint32 result; // dummy variable
    VIAResult rc =  mDllInfo->Call(&result, params);
  }
}

void CaplInstanceData::ArrayValues(uint32 flags, uint32 numberOfDatabytes, uint8 databytes[], uint8 controlcode)
{
  // Prepare the parameters for the call stack of CAPL. The stack grows
  // from top to down, so the first parameter in the parameter list is the last 
  // one in memory. CAPL uses also a 32 bit alignment for the parameters.
  // Arrays uses a 8 byte on the stack, 4 Bytes for the number of element,
  // and 4 bytes for the pointer to the array
  
  uint8 params[16];                           // parameters for call stack, 16 Bytes total    
  memcpy(params+ 0, &controlcode,       1);   // third parameter,                  offset  0, 1 Bytes
  memcpy(params+ 4, &numberOfDatabytes, 4);   // second parameter (array size),    offset  4, 4 Bytes
  memcpy(params+ 8, &databytes,         4);   // second parameter (array pointer), offset  8, 4 Bytes
  memcpy(params+12, &flags,             4);   // first  parameter,                 offset 12, 4 Bytes 

  if(mArrayValues!=NULL)
  {
    uint32 result; // dummy variable
    VIAResult rc =  mArrayValues ->Call(&result, params);
  }

}

CaplInstanceData* GetCaplInstanceData(uint32 handle)
{
  VCaplMap::iterator lSearchResult(gCaplMap.find(handle));
  if ( gCaplMap.end()==lSearchResult )
  {
    return NULL;
  } else {
    return lSearchResult->second;
  }
}

// ============================================================================
// CaplInstanceData
// 
// Data local for a single CAPL Block. 
//
// A CAPL-DLL can be used by more than one CAPL-Block, so every piece of 
// information thats like a global variable in CAPL, must now be wrapped into 
// an instance of an object.
// ============================================================================

void CAPLEXPORT far CAPLPASCAL appInit (uint32 handle)
{
  CaplInstanceData* instance = GetCaplInstanceData(handle);
  if ( NULL==instance )
  {
    VServiceMap::iterator lSearchService(gServiceMap.find(handle));
    if ( gServiceMap.end()!=lSearchService )
    {
      VIACapl* service = lSearchService->second;
      try 
      {
        instance = new CaplInstanceData(service);
      }
      catch ( std::bad_alloc& )
      {
        return; // proceed without change
      }
      instance->GetCallbackFunctions();
      gCaplMap[handle] = instance;
    }
  }
}    

void CAPLEXPORT far CAPLPASCAL appEnd (uint32 handle)
{
  CaplInstanceData* inst = GetCaplInstanceData(handle);
  if (inst==NULL)
  {
    return;
  }
  inst->ReleaseCallbackFunctions();

  delete inst;
  inst = NULL; 
  gCaplMap.erase(handle);
}    

long CAPLEXPORT far CAPLPASCAL appSetValue (uint32 handle, long x)
{
  CaplInstanceData* inst = GetCaplInstanceData(handle);
  if (inst==NULL)
  {
    return -1; 
  }

  return inst->ShowValue(x);
}    

long CAPLEXPORT far CAPLPASCAL appReadData (uint32 handle, long a)
{
  CaplInstanceData* inst = GetCaplInstanceData(handle);
  if (inst==NULL)
  {
    return -1; 
  }

  int16  x = (a>=0) ? +1 : -1;
  uint32 y = abs(a);
  int16  z = (int16)(a & 0x0f000000) >> 24;

  inst->DllVersion("Version 1.1");
  
  inst->DllInfo("DLL: processing");

  uint8 databytes[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

  inst->ArrayValues( 0xaabbccdd, sizeof(databytes), databytes, 0x01);

  return inst->ShowDates( x, y, z);
}    


// ============================================================================
// VIARegisterCDLL
// ============================================================================

VIACLIENT(void) VIARegisterCDLL (VIACapl* service)
{
  uint32    handle;
  VIAResult result;

  if (service==NULL)
  {
    return;
  }

  result = service->GetCaplHandle(&handle);
  if(result!=kVIA_OK)
  {
    return;
  }

  // appInit (internal) resp. "DllInit" (CAPL code) has to follow
  gServiceMap[handle] = service;
}

void ClearAll()
{
  // destroy objects created by this DLL
  // may result from forgotten DllEnd calls
  VCaplMap::iterator lIter=gCaplMap.begin();
  const long cNumberOfEntries = gCaplMap.size();
  long i = 0;
  while ( lIter!=gCaplMap.end() && i<cNumberOfEntries )
  {
    appEnd( (*lIter).first );
    lIter = gCaplMap.begin(); // first element should have vanished
    i++; // assure that no more erase trials take place than the original size of the map
  }

  // just for clarity (would be done automatically)
  gCaplMap.clear();
  gServiceMap.clear();
}

//----------------------------------------------------------------------------
//! \brief SHA256 algorithm initialization
//!
//! - This Function is responsible for initalize SHA256 hashing
//!
//! \pre
//!  nop
//!
//! \post
//!  nop
//!
//! \return unsigned long error/success code
//----------------------------------------------------------------------------
unsigned long CAPLEXPORT far CAPLPASCAL appSHA256_Init(void)
{
	//open an algorithm handle
	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
		&hAlg,
		BCRYPT_SHA256_ALGORITHM,
		NULL,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
		goto Cleanupi;
	}

	//calculate the size of the buffer to hold the hash object
	if (!NT_SUCCESS(status = BCryptGetProperty(
		hAlg,
		BCRYPT_OBJECT_LENGTH,
		(PBYTE)&cbHashObject,
		sizeof(DWORD),
		&cbData,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
		goto Cleanupi;
	}

	//allocate the hash object on the heap
	pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
	if (NULL == pbHashObject)
	{
		wprintf(L"**** memory allocation failed\n");
		goto Cleanupi;
	}

	//calculate the length of the hash
	if (!NT_SUCCESS(status = BCryptGetProperty(
		hAlg,
		BCRYPT_HASH_LENGTH,
		(PBYTE)&cbHash,
		sizeof(DWORD),
		&cbData,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
		goto Cleanupi;
	}

	//allocate the hash buffer on the heap
	pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
	if (NULL == pbHash)
	{
		wprintf(L"**** memory allocation failed\n");
		goto Cleanupi;
	}

	//create a hash
	if (!NT_SUCCESS(status = BCryptCreateHash(
		hAlg,
		&hHash,
		pbHashObject,
		cbHashObject,
		NULL,
		0,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
		goto Cleanupi;
	}
	return status;
Cleanupi:
	if (hAlg)
	{
		BCryptCloseAlgorithmProvider(hAlg, 0);
	}

	if (hHash)
	{
		BCryptDestroyHash(hHash);
	}

	if (pbHashObject)
	{
		HeapFree(GetProcessHeap(), 0, pbHashObject);
	}

	if (pbHash)
	{
		HeapFree(GetProcessHeap(), 0, pbHash);
	}
	return status;
}

//----------------------------------------------------------------------------
//! \brief SHA256 algorithm update
//!
//! - This Function is responsible for update SHA256 hashing
//! - The function hashing all the data that was 'feeded' into the algorithm before appSHA256_Finish is called
//!
//! \param
//!  Message[] - input
//!		-Data to be hashed
//!	 Message_len - input
//!		-data size to be hashed
//!		
//! \pre
//!  appSHA256_Init was called
//!
//! \post
//!  appSHA256_Finish will be called
//!
//! \return unsigned long error/success code
//----------------------------------------------------------------------------
unsigned long CAPLEXPORT far CAPLPASCAL appSHA256_Update(unsigned char Message[], unsigned long Message_len)
{
	//hash some data
	if (!NT_SUCCESS(status = BCryptHashData(
		hHash,
		(PBYTE)Message,
		Message_len,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);
		goto Cleanupu;
	}
	return status;
Cleanupu:
	if (hAlg)
	{
		BCryptCloseAlgorithmProvider(hAlg, 0);
	}

	if (hHash)
	{
		BCryptDestroyHash(hHash);
	}

	if (pbHashObject)
	{
		HeapFree(GetProcessHeap(), 0, pbHashObject);
	}

	if (pbHash)
	{
		HeapFree(GetProcessHeap(), 0, pbHash);
	}
	return status;
}

//----------------------------------------------------------------------------
//! \brief SHA256 algorithm finish
//!
//! - This Function is responsible for finish SHA256 hashing
//! - The return digest/hash is stored in Digest[]
//!
//! \param
//!  Digest[] - output
//!		-Hash of the data that was 'feeded' into the appSHA256_Update function
//!	 Digest_len - output
//!		-hash size (it should be 32 bytes)
//!	
//! \pre
//!  appSHA256_Update was called
//!
//! \post
//!  nop
//!
//! \return unsigned long error/success code
//----------------------------------------------------------------------------
unsigned long CAPLEXPORT far CAPLPASCAL appSHA256_Finish(unsigned char Digest[], unsigned long Digest_len)
{
	if (Digest_len != 32)
	{
		return 0xBAD;
	}
	else
	{
		//Do nothing
	}

	//close the hash
	if (!NT_SUCCESS(status = BCryptFinishHash(
		hHash,
		pbHash,
		cbHash,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
		goto Cleanupf;
	}

	for (unsigned long i = 0; i < Digest_len; i++)
	{
		Digest[i] = pbHash[i];
	}

	wprintf(L"Success!\n");
	return status;
Cleanupf:
	if (hAlg)
	{
		BCryptCloseAlgorithmProvider(hAlg, 0);
	}

	if (hHash)
	{
		BCryptDestroyHash(hHash);
	}

	if (pbHashObject)
	{
		HeapFree(GetProcessHeap(), 0, pbHashObject);
	}

	if (pbHash)
	{
		HeapFree(GetProcessHeap(), 0, pbHash);
	}
	return status;
}

//----------------------------------------------------------------------------
//! \brief appImport_KeyPair
//!
//! - This Function is responsible importing a keypair
//!
//! \param
//!  Key[] - input
//!		- the size must be 104
//!		- [0..8] BLOB header
//!		- [8..72] Public Key (X and Y coordinate)
//!		- [72..104] Private Key
//!	 Key_len - input
//!		-key size must be 104 bytes
//!
//! \pre
//!  
//!
//! \post
//!  appEcdsaSign or appEcdsaVerify can be called
//!
//! \return unsigned long error/success code
//----------------------------------------------------------------------------
unsigned long CAPLEXPORT far CAPLPASCAL appImport_KeyPair(unsigned char Key[], unsigned long Key_len)
{
	if (Key_len != 104)
	{
		return 0xBAD;
	}
	else
	{
		//Do nothing
	}

	
	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
		&hAlgKeyPair,
		BCRYPT_ECDSA_P256_ALGORITHM,
		NULL,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
		
		goto CleanupPrK;
	}
	

	if (!NT_SUCCESS(status = BCryptImportKeyPair(
		hAlgKeyPair,
		NULL,
		BCRYPT_ECCPRIVATE_BLOB,
		&hKeyPair,
		(PUCHAR)Key,
		Key_len,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptImportKeyPair\n", status);
		
		goto CleanupPrK;
	}

	return status;
CleanupPrK:
	if (hAlgKeyPair)
	{
		BCryptCloseAlgorithmProvider(hAlgKeyPair, 0);
	}
	if (hKeyPair)
	{
		BCryptDestroyKey(hKeyPair);
	}
	return status;
}

//----------------------------------------------------------------------------
//! \brief appEcdsaSign
//!
//! - This Function is responsible for creating a signature based on ECDSA NISTP256 algorithm
//!
//! \param
//!  Hash[] - input
//!		- Hash value that has to be signed with the private key (from appImport_KeyPair)
//!	 Hash_len - input
//!		-hash size must be 32 bytes
//!  Signature[] - output
//!		- the signature will be copied into this bytes array
//!	 Signature_len - output
//!		- signature must be 64 bytes
//!
//! \pre
//!  appImport_KeyPair imported a valid keypair
//!
//! \post
//!  nop
//!
//! \return unsigned long error/success code
//----------------------------------------------------------------------------
unsigned long CAPLEXPORT far CAPLPASCAL appEcdsaSign(unsigned char Hash[], unsigned long Hash_len, unsigned char Signature[], unsigned long Signature_len)
{

	if (Hash_len != 32 || Signature_len != 64)
	{
		return 0xBAD;
	}
	else
	{
		//Do nothing
	}

	if (!NT_SUCCESS(status = BCryptSignHash(
		hKeyPair,
		NULL,
		(PUCHAR)Hash,
		Hash_len,
		NULL,
		0,
		&cbSignature,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptSignHash\n", status);
		
		goto CleanupSS;
	}

	//allocate the signature buffer
	pbSignature = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbSignature);
	if (NULL == pbSignature)
	{
		wprintf(L"**** memory allocation failed\n");
		goto CleanupSS;
	}

	if (!NT_SUCCESS(status = BCryptSignHash(
		hKeyPair,
		NULL,
		pbHash,
		cbHash,
		pbSignature,
		cbSignature,
		&cbSignature,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptSignHash\n", status);
		
		goto CleanupSS;
	}

	for (int i = 0; i < 64; i++)
	{
		Signature[i] = pbSignature[i];
	}
	
	return status;
CleanupSS:
	if (pbSignature)
	{
		HeapFree(GetProcessHeap(), 0, pbSignature);
		pbSignature = NULL;
	}
	return status;
}
//----------------------------------------------------------------------------
//! \brief appEcdsaVerify
//!
//! - This Function is responsible for verifying a signature based on the input hash and the imported keypair (verification needs only the public key)
//!
//! \param
//!  Hash[] - input
//!		- Hash value 
//!	 Hash_len - input
//!		-hash size must be 32 bytes
//!  Signature[] - input
//!		- the signature that needs to be verified with public key (from appImport_KeyPair)
//!	 Signature_len - input
//!		- signature must be 64 bytes
//!
//! \pre
//!  appImport_KeyPair imported a valid keypair
//!
//! \post
//!  nop
//!
//! \return unsigned long error/success code
//----------------------------------------------------------------------------
unsigned long CAPLEXPORT far CAPLPASCAL appEcdsaVerify(unsigned char Hash[], unsigned long Hash_len, unsigned char Signature[], unsigned long Signature_len)
{
	if (Hash_len != 32 || Signature_len != 64)
	{
		return 0xBAD;
	}
	else
	{
		//Do nothing
	}

	if (!NT_SUCCESS(status = BCryptVerifySignature(
		hKeyPair,
		NULL,
		(PUCHAR)Hash,
		Hash_len,
		(PUCHAR)Signature,
		Signature_len,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptVerifySignature\n", status);

		goto CleanupVS;
	}

	
	return status;
CleanupVS:
	if (pbSignature)
	{
		HeapFree(GetProcessHeap(), 0, pbSignature);
		pbSignature = NULL;
	}
	return status;
}

// ============================================================================
// CAPL_DLL_INFO_LIST : list of exported functions
//   The first field is predefined and mustn't be changed!
//   The list has to end with a {0,0} entry!
// New struct supporting function names with up to 50 characters
// ============================================================================
CAPL_DLL_INFO4 table[] = {
{CDLL_VERSION_NAME, (CAPL_FARCALL)CDLL_VERSION, "", "", CAPL_DLL_CDECL, 0xabcd, CDLL_EXPORT },

  
  {"dllSHA256_Init",           (CAPL_FARCALL)appSHA256_Init,          "CAPL_DLL","This function will init hashing",'D', 0, "", "", {""}},
  {"dllSHA256_Update",			 (CAPL_FARCALL)appSHA256_Update,	    "CAPL_DLL", "This function will update the hash of a message",'D', 2, "BL", "\001\000", {"Data","noOfBytes"}},
  {"dllSHA256_Finish",			 (CAPL_FARCALL)appSHA256_Finish,	    "CAPL_DLL", "This function will finish the hash of a message",'D', 2, "BL", "\001\000", {"Hash","noOfBytes"}},
  {"dllImport_KeyPair",			 (CAPL_FARCALL)appImport_KeyPair,	    "CAPL_DLL", "This function will finish the hash of a message",'D', 2, "BL", "\001\000", {"KeyBlock","noOfBytes"}},
  {"dllEcdsaSign",			 (CAPL_FARCALL)appEcdsaSign,	    "CAPL_DLL", "This function will Sign a message digest.",'D', 4, "BLBL", "\001\000\001\000", {"Hash","HashSizeBytes","Signature","SignatureSizeBytes"}},
  {"dllEcdsaVerify",			 (CAPL_FARCALL)appEcdsaVerify,	    "CAPL_DLL", "This function will verify an Ecdsa Signature",'D', 4, "BLBL", "\001\000\001\000", {"Hash","HashSizeBytes","Signature","SignatureSizeBytes"}},

{0, 0}
};
CAPLEXPORT CAPL_DLL_INFO4 far * caplDllTable4 = table;

// ============================================================================
// DllMain, entry Point of DLL  
// ============================================================================

BOOL WINAPI DllMain(HINSTANCE handle, DWORD reason, void*)
{     
  switch (reason) 
  {
    case DLL_PROCESS_ATTACH:
    {
      gModuleHandle = handle;
         
      // Get full filename of module
      char path_buffer[_MAX_PATH];
      DWORD result = GetModuleFileName(gModuleHandle, path_buffer,_MAX_PATH);

      // split filename into parts
      char drive[_MAX_DRIVE];
      char dir[_MAX_DIR];
      char fname[_MAX_FNAME];
      char ext[_MAX_EXT];
#if _MSC_VER>=1400 // >= Visual Studio 2005
      _splitpath_s( path_buffer, drive, dir, fname, ext );
      strcpy_s(gModuleName, fname);
#else
      _splitpath( path_buffer, drive, dir, fname, ext );
      strcpy(gModuleName, fname);
#endif
      
      return 1;   // Indicate that the DLL was initialized successfully.
    }

    case DLL_PROCESS_DETACH:                                              
    {
      ClearAll();
      return 1;   // Indicate that the DLL was detached successfully.
    }
  }
  return 1;
}



