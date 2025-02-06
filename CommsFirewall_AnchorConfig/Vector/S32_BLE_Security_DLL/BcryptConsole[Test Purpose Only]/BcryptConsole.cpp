// BcryptConsole.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <Windows.h> // <- Added this
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <map>
#include <bcrypt.h>


#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

int main()
{


	static BCRYPT_ALG_HANDLE       hAlg = NULL;
	static BCRYPT_HASH_HANDLE      hHash = NULL;
	static NTSTATUS                status = STATUS_UNSUCCESSFUL;
	static DWORD                   cbData = 0, cbHash = 0, cbHashObject = 0, cbSignature = 0;
	static PBYTE                   pbHashObject = NULL, pbSignature = NULL;
	static PBYTE                   pbHash = NULL;
	//SHA256 END

	static BCRYPT_ALG_HANDLE       hAlgKeyPair = NULL;
	static BCRYPT_KEY_HANDLE	   hKeyPair = NULL;

	static BCRYPT_ALG_HANDLE       hAlgPrivateKey = NULL;
	static BCRYPT_KEY_HANDLE	   *hPrivateKey = NULL;
	static BCRYPT_ALG_HANDLE       hAlgPublicKey = NULL;
	static BCRYPT_KEY_HANDLE	   *hPublicKey = NULL;

	PBYTE                   KeyBlobPr = NULL;
	DWORD                   KeyBlobPrLength = 0;
	DWORD                   ResultPrLength = 0;

	PBYTE                   KeyBlobPu = NULL;
	DWORD                   KeyBlobPuLength = 0;
	DWORD                   ResultPuLength = 0;

	byte Message[5] = { 0x42, 0x4f, 0x53, 0x43, 0x48 };

	BYTE KeysBob[8 + 64 + 32] = {                   //BLOB: 8 PublicKey: 64 PrivateKey: 32
		0x45,0x43,0x4b,0x32,0x20,0x00,0x00,0x00,    //BLOB header
		0xa7,0xc3,0x53,0x7a,0x7f,0x71,0xbb,0x8a,    //Point X
		0xe4,0x5f,0x13,0xaf,0x31,0x0a,0xf6,0xd5,
		0xbb,0xdb,0xe5,0x96,0xd1,0x09,0xea,0x17,
		0x74,0xb9,0x9d,0xf2,0xc5,0xfd,0x6d,0xef,
		0xe6,0x3a,0x8c,0x8a,0x7b,0xd4,0x6d,0x3a,    //Point Y
		0x6a,0x81,0xf4,0x48,0x75,0x3e,0x94,0x12,
		0xe9,0x98,0xd9,0xa5,0xef,0xee,0x40,0x62,
		0x9a,0x54,0x3f,0x48,0x38,0x9f,0xcb,0x6c,
		0x44,0xe1,0x35,0xa2,0xce,0xc4,0xe3,0x40,	//PrivateKey
		0x79,0x48,0xd1,0x8b,0x4f,0x54,0xbe,0xf9,
		0x4a,0xf3,0x6f,0xea,0xa1,0xc7,0xb3,0x73,
		0x51,0x78,0xc9,0x95,0xcf,0x5a,0x3d,0x5f
	};

	//open an algorithm handle
	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
		&hAlg,
		BCRYPT_SHA256_ALGORITHM,
		NULL,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
		goto Cleanup;
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
		goto Cleanup;
	}

	//allocate the hash object on the heap
	pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
	if (NULL == pbHashObject)
	{
		wprintf(L"**** memory allocation failed\n");
		goto Cleanup;
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
		goto Cleanup;
	}

	//allocate the hash buffer on the heap
	pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
	if (NULL == pbHash)
	{
		wprintf(L"**** memory allocation failed\n");
		goto Cleanup;
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
		goto Cleanup;
	}
	
	//hash some data
	if (!NT_SUCCESS(status = BCryptHashData(
		hHash,
		(PBYTE)Message,
		5,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);
		goto Cleanup;
	}

	//close the hash
	if (!NT_SUCCESS(status = BCryptFinishHash(
		hHash,
		pbHash,
		cbHash,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
		goto Cleanup;
	}
	printf("SHA256 Hash of \"BOSCH\"\r\n");
	for (int i = 0; i < 32; i++)
	{
		printf("%.2x", pbHash[i]);
	}
	printf("\r\n");

	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
		&hAlgKeyPair,
		BCRYPT_ECDSA_P256_ALGORITHM,
		NULL,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
		
	}

	if (!NT_SUCCESS(status = BCryptGenerateKeyPair(
		hAlgKeyPair,
		&hKeyPair,
		256,	//BCRYPT_ECDSA_P256_ALGORITHM		The key size must be 256 bits.
		0
	)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptGenerateKeyPair\n", status);
		
	}

	if (!NT_SUCCESS(status = BCryptFinalizeKeyPair(
		hKeyPair,
		0
		)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptFinalizeKeyPair\n", status);

	}

	if (!NT_SUCCESS(status = BCryptExportKey(
		hKeyPair,
		NULL,
		BCRYPT_ECCPRIVATE_BLOB,
		NULL,
		0,
		&KeyBlobPrLength,
		0
	)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
	}
	
	KeyBlobPr = (PBYTE)HeapAlloc(GetProcessHeap(), 0, KeyBlobPrLength);
	if (NULL == KeyBlobPr)
	{
		wprintf(L"**** memory allocation failed\n");
	}
	
	if (!NT_SUCCESS(status = BCryptExportKey(
		hKeyPair,
		NULL,
		BCRYPT_ECCPRIVATE_BLOB,
		KeyBlobPr,
		KeyBlobPrLength,
		&ResultPrLength,
		0
	)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
	}

	if (!NT_SUCCESS(status = BCryptExportKey(
		hKeyPair,
		NULL,
		BCRYPT_ECCPUBLIC_BLOB,
		NULL,
		0,
		&KeyBlobPuLength,
		0
	)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
	}

	KeyBlobPu = (PBYTE)HeapAlloc(GetProcessHeap(), 0, KeyBlobPuLength);
	if (NULL == KeyBlobPu)
	{
		wprintf(L"**** memory allocation failed\n");
	}

	if (!NT_SUCCESS(status = BCryptExportKey(
		hKeyPair,
		NULL,
		BCRYPT_ECCPUBLIC_BLOB,
		KeyBlobPu,
		KeyBlobPuLength,
		&ResultPuLength,
		0
	)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
	}

	printf("\r\nBLOB PRIVATE ECC\r\n\r\n");
	for (int i = 0; i < KeyBlobPrLength; i++)
	{
		printf("%.2x", KeyBlobPr[i]);
	}
	printf("\r\n");

	printf("\r\nBLOB PUBLIC ECC\r\n\r\n");
	for (int i = 0; i < KeyBlobPuLength; i++)
	{
		printf("%.2x", KeyBlobPu[i]);
	}
	printf("\r\n");


	
	if (!NT_SUCCESS(status = BCryptImportKeyPair(
		hAlgKeyPair,
		NULL,
		BCRYPT_ECCPRIVATE_BLOB,
		&hKeyPair,
		(PUCHAR)&KeysBob,
		104,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptImportKeyPair\n", status);
	}

Cleanup:
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
	
    std::cout << "Hello World!\n";
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
