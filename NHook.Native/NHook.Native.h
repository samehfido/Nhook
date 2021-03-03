// NHook.Native.h

#pragma once

#define BeginNHook namespace NHook { namespace Native {
#define EndNHook } }

#include "mauto_ptr.h"
#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
//#include <http.h>
//#include <cryptuiapi.h>
//#include <WinCrypt.h>
#include<msclr/auto_handle.h>
#include <memory>
#include <msclr\marshal.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <map>
#include <winnt.h>

BeginNHook

#define ASSERT_SUCCESS(result) ULONG r = result; if(r != ERROR_SUCCESS) Win32::Throw(r);
#define ASSERT_TRUE(result) if(!(result)) throw gcnew System::ComponentModel::Win32Exception();

typedef Microsoft::Win32::SafeHandles::SafeFileHandle SafeHandle;
using namespace std;
using namespace System::Security::Cryptography::X509Certificates;
using namespace System;
using namespace System::Net;
using namespace System::Net::Sockets;
using namespace System::Runtime::InteropServices;
using namespace System::ComponentModel;
using namespace System::Collections::Generic;
using namespace msclr::interop;


public ref class Util
{
	public: static  array<Byte>^ ToCSharpArray(BYTE* bytes, int lenght)
		 {
			 auto output = gcnew array<Byte>(lenght);
			 for(int i = 0 ; i < lenght ; i++)
				 output[i] = (Byte)bytes[i];
			 return output;
		 }
		 static BYTE* ToCArray(array<Byte>^ input)
		 {
			 auto ptr = new BYTE[input->Length];
			 for(int i = 0 ; i < input->Length ; i++)
				 ptr[i] = input[i];
			 return ptr;
		 }
};

EndNHook