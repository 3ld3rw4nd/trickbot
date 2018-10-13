/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
//	Author		: elderwand
//	Description	: This module decrypt all modules downloaded by tricbot malware.
//	argument	: Input the file to be decrypted, file will be decrypted in the same directory as input file.
//
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>

#pragma comment (lib, "advapi32")

BOOL CalculateHashValue(BYTE *pbyInBuffer, DWORD dwInBufferSize, BYTE *pbyOutBuffer, DWORD * pdwOutBufferSize);
BOOL DecryptBuffer(BYTE *pbyBuffer, DWORD dwBufferSize, DWORD *pdwDecryptedSize, BYTE *byKey, DWORD dwKeySize, BYTE *byIV, DWORD byIVSize);

int main(int argc, char **argv)
{	
	BOOL bRet = FALSE;
	char sDecrypted_File[0x500];
	BYTE byHashValue[0x1000] = {0};
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwHashValueSize = 0, dwInBufferSize = 0x20, dwFileSize = 0, dwFileSizeLong = 0, dwBytesRead = 0, dwBytesWritten = 0, dwDecryptionSize = 0;

	BYTE *pbyReadBuffer;
	BYTE byInBuffer[0x1000];
	BYTE byKey[0x20], byIV[0x20];

	if (2 != argc)
	{
		printf("Please enter valid file path");
		return FALSE;
	}

	hFile = CreateFileA (argv[1],
						GENERIC_READ | GENERIC_WRITE,
						0,
						NULL,
						OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL,
						NULL);    
	if (INVALID_HANDLE_VALUE == hFile)
	{
		printf("Error in CreateFileA for input file");
		return FALSE;
	}

	dwFileSize = GetFileSize(hFile, &dwFileSizeLong);
	if (0 == dwFileSize || 0x30 > dwFileSize)
	{
		printf("Failed to get file size or file size is less than 30 bytes");
		return FALSE;
	}

	pbyReadBuffer =(BYTE *) VirtualAlloc(NULL, dwFileSize, MEM_COMMIT, PAGE_READWRITE);
	if (NULL == pbyReadBuffer)
	{
		printf("Failed to allocate memory to read file");
		return FALSE;
	}
	
	bRet = ReadFile(hFile, pbyReadBuffer, dwFileSize, &dwBytesRead, NULL);
	if (FALSE == bRet || dwFileSize != dwBytesRead)
	{
		printf("Failed to read file");
		return FALSE;
	}
	
	CloseHandle(hFile);

	//copy first 20 bytes from the file to generate key value
	memcpy(byInBuffer, pbyReadBuffer, dwInBufferSize);
	for (;dwInBufferSize <= sizeof(byInBuffer);)
	{
		dwHashValueSize = 0;
		bRet = CalculateHashValue(byInBuffer, dwInBufferSize, byHashValue, &dwHashValueSize);
		if (FALSE == bRet)
		{
			printf("Failed in CalculateHashValue");
			return FALSE;
		}

		if (sizeof(byInBuffer) == dwInBufferSize)
		{
			break;
		}

		memcpy(byInBuffer + dwInBufferSize, byHashValue, dwHashValueSize);
		dwInBufferSize = dwInBufferSize + dwHashValueSize;
	}

	if (sizeof(byKey) != dwHashValueSize)
	{
		printf("Problem in key value calculation");
		return FALSE;
	}

	//save calculated key value
	memcpy(byKey, byHashValue, sizeof(byKey));

	//copy 20 bytes after leaving first 10 bytes to get intial vector value
	dwInBufferSize = 0x20;
	memcpy(byInBuffer, pbyReadBuffer+0x10, dwInBufferSize);
	for (;dwInBufferSize <= sizeof(byInBuffer);)
	{
		dwHashValueSize = 0;
		bRet = CalculateHashValue(byInBuffer, dwInBufferSize, byHashValue, &dwHashValueSize);
		if (FALSE == bRet)
		{
			printf("Unable to calculate hash");
			return FALSE;
		}

		if (sizeof(byInBuffer) == dwInBufferSize)
		{
			break;
		}

		memcpy(byInBuffer + dwInBufferSize, byHashValue, dwHashValueSize);
		dwInBufferSize = dwInBufferSize + dwHashValueSize;
	}

	if (sizeof(byIV) != dwHashValueSize)
	{
		printf("Problem in initial vector calculation");
		return FALSE;
	}

	memcpy(byIV, byHashValue, sizeof(byIV));

	bRet = DecryptBuffer(pbyReadBuffer+0x30, dwFileSize-0x30, &dwDecryptionSize, byKey, sizeof(byKey), byIV, sizeof(byIV));
	if (FALSE == bRet || 0 == dwDecryptionSize || dwDecryptionSize > dwFileSize)
	{
		printf("Failed in decryption function");
		return FALSE;
	}

	strcpy(sDecrypted_File, argv[1]);
	strcat(sDecrypted_File, "_Decrypted");
	hFile = CreateFileA (sDecrypted_File,
						GENERIC_READ | GENERIC_WRITE,
						0,
						NULL,
						CREATE_ALWAYS,
						FILE_ATTRIBUTE_NORMAL,
						NULL);    
	if (INVALID_HANDLE_VALUE == hFile)
	{
		printf("File Creating Error");
		return FALSE;
	}

	bRet = WriteFile(hFile, pbyReadBuffer+0x30, dwDecryptionSize, &dwBytesWritten, NULL);
	if (FALSE == bRet)
	{
		printf("Failed in WriteFile");
		return FALSE;
	}

	CloseHandle(hFile);
	VirtualFree(pbyReadBuffer, dwFileSize, MEM_RELEASE);
	printf("File decrypted into: %s", sDecrypted_File);

	return 0;
}

BOOL CalculateHashValue(BYTE *pbyInBuffer, DWORD dwInBufferSize, BYTE *pbyOutBuffer, DWORD *pdwOutBufferSize)
{
	BOOL bRet;
	HCRYPTPROV phProv;
	HCRYPTHASH phHash;
	BYTE pbyBuffer[0x10];
	DWORD dwOutBufferSize; 

	bRet = CryptAcquireContextW(&phProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	if (FALSE == bRet)
	{
		printf("Failed in CryptAcquireContextW");
		return FALSE;
	}

	bRet = CryptCreateHash(phProv, CALG_SHA_256, NULL, NULL, &phHash);
	if (FALSE == bRet)
	{
		printf("Failed in CryptCreateHash");
		return FALSE;
	}

	bRet = CryptHashData(phHash, pbyInBuffer, dwInBufferSize, 0);
	if (FALSE == bRet)
	{
		printf("Failed in CryptHashData");
		return FALSE;
	}

	bRet = CryptGetHashParam(phHash, HP_HASHSIZE, pbyBuffer, &dwOutBufferSize, 0);
	if (FALSE == bRet)
	{
		printf("Failed to get hash size");
		return FALSE;
	}

	*pdwOutBufferSize = *(DWORD *)pbyBuffer;
	BYTE *pbyOutBufferTemp = (BYTE *)VirtualAlloc(NULL, *pdwOutBufferSize, MEM_COMMIT, PAGE_READWRITE);
	if(NULL == pbyOutBufferTemp)
	{
		printf("Failed in allocating memory");
		return FALSE;
	}

	bRet = CryptGetHashParam(phHash, HP_HASHVAL, pbyOutBufferTemp, pdwOutBufferSize, 0);
	if (FALSE == bRet)
	{
		printf("Failed in CryptGetHashParam");
		return FALSE;
	}

	memcpy(pbyOutBuffer, pbyOutBufferTemp, *pdwOutBufferSize);

	VirtualFree(pbyOutBufferTemp, *pdwOutBufferSize, MEM_RELEASE);

	return TRUE;
}

BOOL DecryptBuffer(BYTE *pbyBuffer, DWORD dwBufferSize, DWORD *pdwDecryptedSize, BYTE *byKey, DWORD dwKeySize, BYTE *byIV, DWORD byIVSize)
{
	BOOL bRet = FALSE;
	DWORD dwDecyptedSize = 0;
	HCRYPTPROV phProv = {0};
	PUBLICKEYSTRUC pkBlobHeaded = {0};
	BYTE byImportKeyData[0x2C];
	BYTE byParamBuffer[0x20] = {0};
	HCRYPTKEY hCryptKey = NULL;
	

	bRet = CryptAcquireContextW(&phProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	if (FALSE == bRet)
	{
		printf("Failed in CryptAcquireContextW\n");
		return FALSE;
	}

	memset(&pkBlobHeaded, 0, sizeof(pkBlobHeaded));
	pkBlobHeaded.bType = PLAINTEXTKEYBLOB;
	pkBlobHeaded.bVersion = 0x2;
	pkBlobHeaded.aiKeyAlg = CALG_AES_256;

	memcpy(byImportKeyData, &pkBlobHeaded, sizeof(pkBlobHeaded));
	memcpy(byImportKeyData+sizeof(pkBlobHeaded), &dwKeySize, sizeof(dwKeySize));
	memcpy(byImportKeyData+sizeof(pkBlobHeaded)+sizeof(dwKeySize), byKey, dwKeySize);
	bRet = CryptImportKey(phProv, byImportKeyData, sizeof(byImportKeyData), 0, CRYPT_EXPORTABLE, &hCryptKey); 
	if (FALSE == bRet)
	{
		printf("Failed in CryptImportKey\n");
		return FALSE;
	}

	byParamBuffer[0] = CRYPT_MODE_CBC;
	bRet = CryptSetKeyParam(hCryptKey, KP_MODE, byParamBuffer, 0);
	if (FALSE == bRet)
	{
		printf("Failed in CryptSetKeyParam\n");
		return FALSE;
	}

	if (sizeof(byParamBuffer) != byIVSize)
	{
		printf("Initial Vector and param buffer size if different\n");
		return FALSE;
	}

	memcpy(byParamBuffer, byIV, byIVSize);
	bRet = CryptSetKeyParam(hCryptKey, KP_IV, byParamBuffer, 0);
	if (FALSE == bRet)
	{
		printf("Failed in CryptSetKeyParam\n");
		return FALSE;
	}

	dwDecyptedSize = dwBufferSize;
	bRet = CryptDecrypt(hCryptKey, 0, 1, 0, pbyBuffer, &dwDecyptedSize);
	if (FALSE == bRet || dwDecyptedSize > dwBufferSize)
	{
		printf("Failed in decryption\n");
		return FALSE;
	}

	*pdwDecryptedSize = dwDecyptedSize;

	return TRUE;
}
