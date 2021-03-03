#include "NHook.Native.h"


BeginNHook

	public ref class ProcessInformation
{
public:
	ProcessInformation(LPPROCESS_INFORMATION processInformation)
	{
		_ProcessHandle = gcnew SafeHandle(IntPtr(processInformation->hProcess),true);
		_ThreadHandle = gcnew SafeHandle(IntPtr(processInformation->hThread),true);
		_ProcessId = GetProcessId(processInformation->hProcess);
	}
private: UInt32 _ProcessId;
public: property UInt32 ProcessId
		{
			UInt32 get()
			{
				return _ProcessId;
			}
		}

private: SafeHandle^ _ProcessHandle;
public: property SafeHandle^ ProcessHandle
		{
			SafeHandle^ get()
			{
				return _ProcessHandle;
			}
		}
private: SafeHandle^ _ThreadHandle;
public: property SafeHandle^ ThreadHandle
		{
			SafeHandle^ get()
			{
				return _ThreadHandle;
			}
		}
};

public enum class DebugEventType
{
	CreateProcessEvent = 3,
	CreateThreadEvent=2,
	ExceptionEvent= 1,
	ExitProcessEvent = 5,
	ExitThreadEvent=4,
	LoadDllEvent = 6,
	DebugStringEvent=8,
	RipEvent=9,
	UnloadDllEvent = 7,

};

public enum class ExceptionReason : UINT32
{
	ExceptionBreakpoint = EXCEPTION_BREAKPOINT,
	AccessViolation = EXCEPTION_ACCESS_VIOLATION,
	ExceptionArrayBoundExceeded = EXCEPTION_ARRAY_BOUNDS_EXCEEDED,
	ExceptionDataTypeMisalignment = EXCEPTION_DATATYPE_MISALIGNMENT,
	ExceptionSingleStep = EXCEPTION_SINGLE_STEP
};


public ref class DebugEvent
{
public: DebugEvent(LPDEBUG_EVENT debugEvent)
		{
			_EventType = (DebugEventType)debugEvent->dwDebugEventCode;
			_ThreadId = debugEvent->dwThreadId;
			_ProcessId = debugEvent->dwProcessId;
		}

private: DebugEventType _EventType;
public: property DebugEventType EventType
		{
			DebugEventType get()
			{
				return _EventType;
			}
		}
private: UINT32 _ProcessId;
public: property UINT32 ProcessId
		{
			UINT32 get()
			{
				return _ProcessId;
			}
		}
private: UInt32 _ThreadId;
public: property UInt32 ThreadId
		{
			UInt32 get()
			{
				return _ThreadId;
			}
		}

public: virtual String^ ToString() override
		{
			return Enum::GetName(DebugEventType::typeid, EventType);
		}
};

public ref class Detail
{
public:Detail(DebugEventType eventType)
	   {
		   _EventType = eventType;
	   }
private: DebugEventType _EventType;
public: property DebugEventType EventType
		{
			DebugEventType get()
			{
				return _EventType;
			}
		}
};
generic<typename TDetail> where TDetail:Detail
	public ref class DebugEventEx : DebugEvent
{
public:DebugEventEx(LPDEBUG_EVENT debugEvent, TDetail details):DebugEvent(debugEvent)
	   {
		   _Details = details;
	   }

private: TDetail _Details;
public: property TDetail Details
		{
			TDetail get()
			{
				return _Details;
			}
		}
};

public ref class MemoryUtil
{
public:static void WriteMemory(IntPtr processHandle, IntPtr baseAddress, array<Byte>^ input)
	   {
		   mauto_handle<BYTE> bytes(Util::ToCArray(input));
		   SIZE_T readen;
		   ASSERT_TRUE(WriteProcessMemory(processHandle.ToPointer(),baseAddress.ToPointer(),bytes.get(),input->Length,&readen));
	   }
	   static array<Byte>^ ReadMemory(IntPtr processHandle, IntPtr baseAddress, int size)
	   {
		   mauto_handle<BYTE> bytes(new BYTE[size]);
		   SIZE_T readen;
		   ASSERT_TRUE(ReadProcessMemory(processHandle.ToPointer(),baseAddress.ToPointer(),bytes.get(),size,&readen));
		   return Util::ToCSharpArray(bytes.get(),readen);
	   }
};

public ref class ThreadContext
{
public: ThreadContext(_CONTEXT* ctx)
		{
			_EIP = IntPtr((int)ctx->Eip);
		}
private: IntPtr _EIP;
public: property IntPtr EIP
		{
			IntPtr get()
			{
				return _EIP;
			}
		}
};
public ref class ExceptionRecord
{
public: ExceptionRecord(LPEXCEPTION_RECORD record)
		{
			_Reason = (ExceptionReason)record->ExceptionCode;
			_Address = IntPtr(record->ExceptionAddress);
			if(record->ExceptionRecord != NULL)
				_InnerException = gcnew ExceptionRecord(record->ExceptionRecord);
		}
private: IntPtr _Address;
public: property IntPtr Address
		{
			IntPtr get()
			{
				return _Address;
			}
		}
private: ExceptionRecord^ _InnerException;
public: property ExceptionRecord^ InnerException
		{
			ExceptionRecord^ get()
			{
				return _InnerException;
			}
		}
private: ExceptionReason _Reason;
public: property ExceptionReason Reason
		{
			ExceptionReason get()
			{
				return _Reason;
			}
		}
};

public ref class CreateThreadDetail : Detail
{
public:CreateThreadDetail(ProcessInformation^ processInformation, LPCREATE_THREAD_DEBUG_INFO debugInfo):Detail(DebugEventType::CreateThreadEvent)
	   {
		   _ThreadHandle = gcnew SafeHandle(IntPtr(debugInfo->hThread),false);
	   }
private: SafeHandle^ _ThreadHandle;
public: property SafeHandle^ ThreadHandle
		{
			SafeHandle^ get()
			{
				return _ThreadHandle;
			}
		}
};

public ref class ExitProcessDetail: Detail
{
public:ExitProcessDetail(ProcessInformation^ processInformation, LPEXIT_PROCESS_DEBUG_INFO debugInfo):Detail(DebugEventType::ExitProcessEvent)
	   {
		   _ExitCode = (int)debugInfo->dwExitCode;
	   }
private: int _ExitCode;
public: property int ExitCode
		{
			int get()
			{
				return _ExitCode;
			}
		}
};
public ref class ExceptionDetail : Detail
{
public:ExceptionDetail(ProcessInformation^ processInformation, LPEXCEPTION_DEBUG_INFO debugInfo):Detail(DebugEventType::ExceptionEvent)
	   {
		   _IsFirstChance = debugInfo->dwFirstChance != 0;
		   _Exception = gcnew ExceptionRecord(&debugInfo->ExceptionRecord);
	   }

private: ExceptionRecord^ _Exception;
public: property ExceptionRecord^ Exception
		{
			ExceptionRecord^ get()
			{
				return _Exception;
			}
		}

private: bool _IsFirstChance;
public: property bool IsFirstChance
		{
			bool get()
			{
				return _IsFirstChance;
			}
		}
};


public ref class LoadDllDetail : Detail
{
public:LoadDllDetail(ProcessInformation^ processInformation, LPLOAD_DLL_DEBUG_INFO debugInfo):Detail(DebugEventType::LoadDllEvent)
	   {
		   _ModuleHandle = gcnew SafeHandle(IntPtr(debugInfo->hFile),true);
		   _BaseOfModule = IntPtr(debugInfo->lpBaseOfDll);

		   TCHAR path[MAX_PATH*3];
		   GetFinalPathNameByHandle(debugInfo->hFile,path,MAX_PATH*3,0);
		   _Location = marshal_as<String^>(path);
		   _Location = _Location->Replace("\\\\?\\","");

		   if(debugInfo->lpImageName != NULL)
		   {
			   SIZE_T readen;
			   wchar_t data[MAX_PATH + 1];
			   ZeroMemory(data,sizeof(data));
			   ASSERT_TRUE(::ReadProcessMemory((HANDLE)processInformation->ProcessHandle->DangerousGetHandle().ToInt32(), debugInfo->lpImageName, data,sizeof(void*),&readen));
			   if(((void**)data)[0] != NULL)
			   {
				   ASSERT_TRUE(::ReadProcessMemory((HANDLE)processInformation->ProcessHandle->DangerousGetHandle().ToInt32(), ((void**)data)[0], data,sizeof(data),&readen));
				   if(debugInfo->fUnicode)
					   _ImageName = marshal_as<String^,const wchar_t*>((const wchar_t*)data);
				   else
					   _ImageName = marshal_as<String^,const char*>((const char*)data);
			   }
		   }
	   }

private: String^ _Location;
public: property String^ Location
		{
			String^ get()
			{
				return _Location;
			}
		}

private: String^ _ImageName;
public: property String^ ImageName
		{
			String^ get()
			{
				return _ImageName;
			}
		}

private: SafeHandle^ _ModuleHandle;
public: property SafeHandle^ ModuleHandle
		{
			SafeHandle^ get()
			{
				return _ModuleHandle;
			}
			void set(SafeHandle^ value)
			{
				_ModuleHandle = value;
			}
		}
private: IntPtr _BaseOfModule;
public: property IntPtr BaseOfModule
		{
			IntPtr get()
			{
				return _BaseOfModule;
			}
		}
};
public ref class Helper
{
public: static ProcessInformation^ DebugActiveProcess(int pid)
		{
			ASSERT_TRUE(::DebugActiveProcess(pid));
			auto process = System::Diagnostics::Process::GetProcessById(pid);
			PROCESS_INFORMATION info;
			info.dwProcessId = process->Id;
			info.dwThreadId = process->Threads[0]->Id;
			info.hProcess = OpenProcess(PROCESS_ALL_ACCESS,false,process->Id);
			info.hThread = OpenThread(THREAD_ALL_ACCESS,false, process->Threads[0]->Id);
			return gcnew ProcessInformation(&info);
		}
public:
	static ProcessInformation^ StartDebugProcess(String^ appPath)
	{
		marshal_context context;
		STARTUPINFO startupInfo = {0};
		startupInfo.cb = sizeof(STARTUPINFO);

		PROCESS_INFORMATION processInformation = {0};
		auto directory = System::IO::Path::GetDirectoryName(appPath);
		ASSERT_TRUE(CreateProcess(context.marshal_as<LPCTSTR>(appPath),
			NULL, 
			NULL,
			NULL,
			false,
			CREATE_DEFAULT_ERROR_MODE | CREATE_NEW_CONSOLE | DEBUG_ONLY_THIS_PROCESS | NORMAL_PRIORITY_CLASS,
			NULL,
			context.marshal_as<LPCTSTR>(directory),
			&startupInfo,
			&processInformation));
		return gcnew ProcessInformation(&processInformation);
	}
	static void Continue(DebugEvent^ debugEvent, bool handleException)
	{
		ContinueDebugEvent(debugEvent->ProcessId, debugEvent->ThreadId, handleException ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED);
	}
	static void DebugActiveProcessStop(ProcessInformation^ info)
	{
		::DebugActiveProcessStop(info->ProcessId);
	}
	static void DebugSetProcessKillOnExit(bool killOnExit)
	{
		::DebugSetProcessKillOnExit(false);
	}

	static void StepByStep(SafeHandle^ threadHandle, bool mode)
	{
		_CONTEXT ctx;
		ZeroMemory(&ctx,sizeof(_CONTEXT));
		ctx.ContextFlags = CONTEXT_FULL;
		ASSERT_TRUE(::GetThreadContext((HANDLE)threadHandle->DangerousGetHandle().ToPointer(), &ctx));
		if(mode)
			ctx.EFlags |= 0x100;
		else
			ctx.EFlags &= ~0x100;
		::SetThreadContext((HANDLE)threadHandle->DangerousGetHandle().ToPointer(), &ctx);
	}
	static ThreadContext^ GetThreadContext(SafeHandle^ threadHandle)
	{
		_CONTEXT ctx;
		ZeroMemory(&ctx,sizeof(_CONTEXT));
		ctx.ContextFlags = CONTEXT_FULL;
		ASSERT_TRUE(::GetThreadContext((HANDLE)threadHandle->DangerousGetHandle().ToPointer(), &ctx));
		return gcnew ThreadContext(&ctx);
	}
	static void ChangeEIPTo(SafeHandle^ threadHandle, IntPtr address)
	{
		_CONTEXT ctx;
		ZeroMemory(&ctx,sizeof(_CONTEXT));
		ctx.ContextFlags = CONTEXT_FULL;
		ASSERT_TRUE(::GetThreadContext((HANDLE)threadHandle->DangerousGetHandle().ToPointer(), &ctx));
		ctx.Eip = (DWORD)address.ToPointer();
		ASSERT_TRUE(::SetThreadContext((HANDLE)threadHandle->DangerousGetHandle().ToPointer(), &ctx));
	}
	static DebugEvent^ WaitForEvent(ProcessInformation^ processInformation, TimeSpan timeout)
	{
		DEBUG_EVENT dbgEvent;
		BOOL result;
		if(timeout == TimeSpan::MaxValue)
			result = WaitForDebugEvent(&dbgEvent, INFINITE);
		else
			result = WaitForDebugEvent(&dbgEvent, (DWORD)timeout.TotalMilliseconds);
		if(!result)
			return nullptr;

		if(dbgEvent.dwDebugEventCode == (DWORD)DebugEventType::LoadDllEvent)
			return gcnew DebugEventEx<LoadDllDetail^>(&dbgEvent, gcnew LoadDllDetail(processInformation, &dbgEvent.u.LoadDll));
		if(dbgEvent.dwDebugEventCode == (DWORD)DebugEventType::ExceptionEvent)
			return gcnew DebugEventEx<ExceptionDetail^>(&dbgEvent, gcnew ExceptionDetail(processInformation, &dbgEvent.u.Exception));
		if(dbgEvent.dwDebugEventCode == (DWORD)DebugEventType::CreateThreadEvent)
			return gcnew DebugEventEx<CreateThreadDetail^>(&dbgEvent, gcnew CreateThreadDetail(processInformation, &dbgEvent.u.CreateThread));
		if(dbgEvent.dwDebugEventCode == (DWORD)DebugEventType::ExitProcessEvent)
			return gcnew DebugEventEx<ExitProcessDetail^>(&dbgEvent, gcnew ExitProcessDetail(processInformation, &dbgEvent.u.ExitProcess));
		return gcnew DebugEvent(&dbgEvent);
	}

};

EndNHook