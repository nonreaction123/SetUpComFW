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
//! \brief SeednKey dll for CANoe
//!
//! Module Description
//!     Seed & Key DLL with extended interface and options argument
//!     GenerateKeyExOpt() C++ function will be the interface for diagGenerateKeyFromSeed() and TestWaitForGenerateKeyFromSeed() functions in CAPL
//!     Either use the "char ecuQualifier[]" first parameter of diagGenerateKeyFromSeed (This will identify which diagnostics ecu seednkey.dll will be used)
//!			or use DiagConnectChannel(char ecuQualifier[]); // form 2 from your CAPL script or Test script
//!			long TestWaitForUnlockEcu(char ecuQualifier[], dword securityLevel); // form 2 might also be used  with on DiagRequest/on DiagResponse event handler.
//!
//----------------------------------------------------------------------------

#include <windows.h>
#include "GenerateKeyExOpt.h"

#include <stdio.h>
#include <stdlib.h>
#include <map>

#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define NULL 0
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

#define KEYPAIR_SIZE (104U)
#define KEYPAIR_VARIANT_SIZE (2U)

#define UDS_INCAR_LVL (0x65U)
#define UDS_BOSCH_LVL  (0x61U)

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

typedef struct
{
	const char* Variant_p;
	BYTE *KeyPair_p;
}KeyPair_Variant_st;

//Development Keys
BYTE UDS_inCar[KEYPAIR_SIZE] = { 0x45,0x43,0x53,0x32,0x20,0x00,0x00,0x00,0x10,0x42,0xa5,0xda,0xdf,0x07,0x22,0x6d,0x16,0xbe,0x11,0x51,0x3b,0x47,0x52,0x88,0x01,0x28,0xa9,0xc5,0x49,0xa1,0xc0,0xcf,0xd6,0xd2,0xed,0xba,0x36,0xcc,0x59,0xbc,0xc0,0x04,0x57,0x4b,0xc4,0x7a,0x99,0x32,0x56,0xb2,0xb9,0x1f,0x36,0xae,0xc0,0x40,0xcb,0xf5,0x2b,0x8f,0x9a,0xed,0xc9,0x3d,0x35,0x85,0xd5,0x98,0x74,0x89,0xf7,0x66,0xe4,0xc3,0x2b,0x6a,0x84,0xbc,0x24,0x3a,0xdf,0xfc,0xda,0x64,0xf3,0xbf,0x44,0x96,0x97,0xad,0xc6,0x52,0x90,0x73,0x54,0x4a,0xd1,0x78,0xf8,0x9b,0x8d,0xfb,0xa6,0x57 };
BYTE UDS_Bosch[KEYPAIR_SIZE] = { 0x45,0x43,0x53,0x32,0x20,0x00,0x00,0x00,0x49,0x52,0x23,0xfd,0x04,0x4a,0x02,0xd6,0xf7,0xbe,0xb5,0xa8,0x9f,0x1d,0xd3,0x17,0x9e,0x0f,0x23,0x54,0x41,0xc5,0x4e,0xbd,0x37,0x20,0x39,0xcc,0x24,0x71,0xed,0x19,0x69,0xc3,0x9e,0xb5,0x2d,0x1b,0x3b,0xe3,0xf3,0xe0,0xd4,0xae,0x59,0xdd,0x81,0xa3,0xe6,0x67,0x25,0x5f,0x26,0x04,0x40,0xdf,0x66,0x15,0x32,0x23,0xb2,0xeb,0xf4,0xd6,0x0c,0x8d,0x19,0x98,0xda,0x96,0x2a,0x3a,0xb3,0x4d,0x6b,0x3f,0xe5,0xb2,0x8c,0x24,0xf9,0xc0,0x20,0x09,0x9c,0x74,0xf0,0x5c,0x6d,0x70,0x92,0x96,0x65,0x47,0xdf,0x55 };

KeyPair_Variant_st KeyPair_Variant[KEYPAIR_VARIANT_SIZE] =
{
	
	{"UDS_INCAR_LVL",UDS_inCar},
	{"UDS_BOSCH_LVL",UDS_Bosch}

};


unsigned long  appSHA256_Init(void);
unsigned long appSHA256_Update(unsigned char Message[], unsigned long Message_len);
unsigned long  appSHA256_Finish(void);
unsigned long appImport_KeyPair(unsigned char Key[], unsigned long Key_len);
unsigned long  appEcdsaSign(unsigned char Hash[], unsigned long Hash_len);

KEYGENALGO_API VKeyGenResultExOpt GenerateKeyExOpt(
  const unsigned char*  ipSeedArray,            // Array for the seed [in]
  unsigned int          iSeedArraySize,         // Length of the array for the seed [in]
  const unsigned int    iSecurityLevel,         // Security level [in]
  const char*           ipVariant,              // Name of the active variant [in]
  const char*           ipOptions,              // Optional parameter which might be used for OEM specific information [in]
  unsigned char*        iopKeyArray,            // Array for the key [in, out]
  unsigned int          iMaxKeyArraySize,       // Maximum length of the array for the key [in]
  unsigned int&         oActualKeyArraySize)    // Length of the key [out]
{
	bool VarianCheckFail = TRUE;
  // Check the input arguments
  if (iSecurityLevel != UDS_BOSCH_LVL && iSecurityLevel != UDS_INCAR_LVL)
    return KGREO_SecurityLevelInvalid;

  if ((64U > iMaxKeyArraySize) || (iSeedArraySize != 48U))
    return KGREO_BufferToSmall;
  
  //Hash the seed, result is stored in pbHash
  appSHA256_Init();
  appSHA256_Update((PBYTE)ipSeedArray, iSeedArraySize);
  appSHA256_Finish();

  if (!strcmp(ipVariant, "CommonDiagnostics"))	//If SeednKey dll is used from Diagnostics (Workaround)
  {
	  if (iSecurityLevel == UDS_BOSCH_LVL)
	  {
		  appImport_KeyPair((PUCHAR)KeyPair_Variant[1].KeyPair_p, KEYPAIR_SIZE);	//Import Bosch KeyPair 
	  }
	  else if (iSecurityLevel == UDS_INCAR_LVL)
	  {
		  appImport_KeyPair((PUCHAR)KeyPair_Variant[0].KeyPair_p, KEYPAIR_SIZE);	//Import InCar KeyPair 
	  }
	  else
	  {

	  }

	  appEcdsaSign((PUCHAR)pbHash, 32);	//sign the hash with the Private Key from KeyPair handler, result is stored in pbSignature

	  memcpy(iopKeyArray, pbSignature, 64);
	  
  }
  else    //If SeednKey dll is used from CAPL script (Workaround)
  {
	  for (int i = 0; i < KEYPAIR_VARIANT_SIZE; i++)
	  {
		  if (!strcmp(ipVariant, KeyPair_Variant[i].Variant_p))	//Variant is in the list
		  {
			  VarianCheckFail = FALSE;	//Dont return \w KGREO_VariantInvalid
		  }
	  }

	  if (VarianCheckFail == TRUE)
	  {
		  return KGREO_VariantInvalid;	//return invalid variant
	  }

	  for (int i = 0; i < KEYPAIR_VARIANT_SIZE; i++)
	  {
		if (!strcmp(ipVariant, KeyPair_Variant[i].Variant_p))	//Variant is in the list
		{
			appImport_KeyPair((PUCHAR)KeyPair_Variant[i].KeyPair_p, KEYPAIR_SIZE);	//Import KeyPair 
		}
	  }

	  appEcdsaSign((PUCHAR)pbHash, 32);	//sign the hash with the Private Key from KeyPair handler, result is stored in pbSignature
	  memcpy(iopKeyArray, pbSignature, 64);

  }


  oActualKeyArraySize = 64;
  return KGREO_Ok;
}


unsigned long  appSHA256_Init(void)
{
	//open an algorithm handle
	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
		&hAlg,
		BCRYPT_SHA256_ALGORITHM,
		NULL,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);

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

	}

	//allocate the hash object on the heap
	pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
	if (NULL == pbHashObject)
	{
		wprintf(L"**** memory allocation failed\n");

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

	}

	//allocate the hash buffer on the heap
	pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
	if (NULL == pbHash)
	{
		wprintf(L"**** memory allocation failed\n");

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

	}
	return status;

}

unsigned long appSHA256_Update(unsigned char Message[], unsigned long Message_len)
{
	//hash some data
	if (!NT_SUCCESS(status = BCryptHashData(
		hHash,
		(PBYTE)Message,
		Message_len,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);

	}
	return status;

}

unsigned long  appSHA256_Finish(void)
{


	//close the hash
	if (!NT_SUCCESS(status = BCryptFinishHash(
		hHash,
		pbHash,
		cbHash,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
		
	}

	wprintf(L"Success!\n");
	return status;

}

unsigned long appImport_KeyPair(unsigned char Key[], unsigned long Key_len)
{
	if (Key_len != KEYPAIR_SIZE)
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

		
	}

	return status;

}

unsigned long  appEcdsaSign(unsigned char Hash[], unsigned long Hash_len)
{

	if (Hash_len != 32 )
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
	}

	//allocate the signature buffer
	pbSignature = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbSignature);
	if (NULL == pbSignature)
	{
		wprintf(L"**** memory allocation failed\n");
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
	}



	return status;

}

