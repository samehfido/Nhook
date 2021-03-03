#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <float.h>


#include "NHook.Native.h"
#include "disasm.h"


BeginNHook


[Serializable]
	public ref class AssemblerException : Exception
	{
	public: AssemblerException()
		{
		}
	public: AssemblerException(String^ message) : Exception(message)
		{
		}
	public: AssemblerException(String^ message, Exception^ inner) : Exception(message, inner)
		{
		}
	protected: AssemblerException(
		  System::Runtime::Serialization::SerializationInfo^ info,
		  System::Runtime::Serialization::StreamingContext context)
			: Exception(info, context)
		{
		}
	};
public ref class DisasmResult
{
private: static Byte GetHexVal(char hex) {
			 int val = (int)hex;
			 //For uppercase A-F letters:
			 return val - (val < 58 ? 48 : 55);
			 //For lowercase a-f letters:
			 //return val - (val < 58 ? 48 : 87);
			 //Or the two combined, but a bit slower:
			 //return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
		 }
private: static array<Byte>^ StringToByteArrayFastest(String^ hex) {
			 if (hex->Length % 2 == 1)
				 throw gcnew Exception("The binary key cannot have an odd number of digits");

			 array<Byte>^ arr = gcnew array<Byte>(hex->Length >> 1);

			 for (int i = 0; i < hex->Length >> 1; ++i)
			 {
				 arr[i] = (Byte)((GetHexVal((char)hex[i << 1]) << 4) + (GetHexVal((char)hex[(i << 1) + 1])));
			 }
			 return arr;
		 }


public: DisasmResult(String^ cmd, t_asmmodel* native_result){
			_Instruction = cmd;
			//_Size = native_result->length;
			_Bytes = Util::ToCSharpArray((BYTE*)native_result->code,native_result->length);
		}
public: DisasmResult(t_disasm* native_result)
		{
			_Instruction = marshal_as<String^>(native_result->result);
			auto dump = marshal_as<String^>(native_result->dump);
			dump = dump->Replace(" ",String::Empty)->Replace(":",String::Empty);
			//_Size = dump->Length / 2;
			_Bytes = DisasmResult::StringToByteArrayFastest(dump);
		}
private: String^ _Instruction;
public: property String^ Instruction
		{
			String^ get()
			{
				return _Instruction;
			}
			void set(String^ value)
			{
				_Instruction = value;
			}
		}
private: array<Byte>^ _Bytes;
public: property array<Byte>^ Bytes
		{
			array<Byte>^ get()
			{
				return _Bytes;
			}
		}
};
public ref class DisasmWrapper
{
private:static String^ ToString(int errorCode)
		{
			switch (errorCode)
			{
			case DAE_BADCMD:
				return "Unrecognized command";
			case DAE_CROSS:
				return "Command crosses end of memory block";
			case DAE_BADSEG:
				return "Undefined segment register";
			case DAE_MEMORY:
				return "Register where only memory allowed";
			case DAE_REGISTER:
				return "Memory where only register allowed";
			case DAE_INTERN:
				return "Internal error";
			default:
				return "Unknown reason";
			}
		}
public: static DisasmResult^ Disasm(array<Byte>^ bytes, int offset)
		{
			if(offset >= bytes->Length)
				return nullptr;
			t_disasm native_result;
			auto_ptr<BYTE> b(Util::ToCArray(bytes));
			::Disasm((char*)b.get() + offset,bytes->Length,0,&native_result, DISASM_FILE);
			if(native_result.error != DAE_NOERR)
			{
				throw gcnew AssemblerException("Impossible to disassemble because : " + ToString(native_result.error));
			}
			return gcnew DisasmResult(&native_result);
		}
	
public: static DisasmResult^ Disasm(array<Byte>^ bytes)
		{
			return Disasm(bytes,0);
		}
public: static DisasmResult^ Assemble(String^ str)
		{
			char error[TEXTLEN];
			ZeroMemory(error,sizeof(error));
			t_asmmodel output;
			ZeroMemory(&output,sizeof(output));
			marshal_context ctx;
			auto result = ::Assemble((char*)ctx.marshal_as<const char*>(str),
				0,
				&output,
				0,
				0,
				error);
			if(result <=0)
				throw gcnew AssemblerException("Invalid x86 instruction : " + marshal_as<String^>(error));
			return gcnew DisasmResult(str, &output);
		}




};

EndNHook