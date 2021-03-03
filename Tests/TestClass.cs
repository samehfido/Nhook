using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using Mono.Cecil.PE;
using NHook;
using NHook.Native;
using Xunit;

namespace Tests
{

	public class TestClass
	{
		const string SimpleCrackMe = "TestData/SimpleCrackMe.exe";
		[Fact]
		public void CanGetNtHeadersFromFile()
		{
			var image = Image.ReadFromFile("TestData/BeaEngine.dll");
			Assert.Equal<uint>(0x10000000, image.NtHeader.ImageBase);
			Assert.Equal<uint>(0x00041000, image.NtHeader.ImageSize);
			Assert.Equal<uint>(0x00034DB0, image.NtHeader.EntryPoint);
		}
		[Fact]
		public void CanParseVirtualSizeCorrectly()
		{
			var image = Image.ReadFromFile("TestData/BeaEngine.dll");
			Assert.Equal<uint>(0x2578, image.Sections[2].VirtualSize);
		}
		[Fact]
		public void CanDisassemble()
		{
			var testData = new object[,]
			{
				{ new byte[]{ 0xCC } , "INT3" },
				{ new byte[]{ 0x8B, 0xEC } , "MOV EBP,ESP" },
				{ new byte[]{ 0x83,0xC4,0x04 } , "ADD ESP,4" },
				{ new byte[]{ 0x90}, "NOP"}
			};

			for(int i = 0 ; i < testData.GetLength(0) ; i++)
			{
				var shellCode = (byte[])testData[i, 0];
				var instruction = (string)testData[i, 1];
				var actual = DisasmWrapper.Disasm(shellCode);
				Assert.Equal(instruction, actual.Instruction);
				Assert.Equal(shellCode.Length, actual.Bytes.Length);
				for(int y = 0 ; y < shellCode.Length ; y++)
				{
					Assert.Equal(shellCode[y], actual.Bytes[y]);
				}
			}

			try
			{
				DisasmWrapper.Disasm(new byte[] { 0xF1, 0x00, 0x00 });
				Assert.True(false, "Should have thrown invalid x86 instruction");
			}
			catch(AssemblerException)
			{
			}
		}

		[Fact]
		public void CanReadExportTable()
		{
			var image = Image.ReadFromFile("BeaEngine.dll");
			var expected = new object[,]
			{
				{0x34A49,0,"_BeaEngineRevision@0"},
				{0x34A3E,1,"_BeaEngineVersion@0"},
				{0x320F8,2,"_Disasm@4"}
			};

			var exports = image.GetExports();
			Assert.Equal(expected.GetLength(0), exports.Length);
			for(int i = 0 ; i < exports.Length ; i++)
			{
				var export = exports[i];
				Assert.Equal((int)expected[i,0], (int)export.RVA.Address);
				Assert.Equal((int)expected[i,1], export.Ordinal);
				Assert.Equal((string)expected[i,2], export.Name);
			}
		}

		[Fact]
		public void CanDisassembleMultiple()
		{
			var shellCode = new byte[] { 0xCC, 0x8B, 0xEC, 0x83, 0xC4, 0x04 };
			var instructions = new string[] { "INT3", "MOV EBP,ESP", "ADD ESP,4" };
			Disassembler disassembler = new Disassembler();
			var result = disassembler.Disassemble(shellCode).ToList();
			Assert.Equal(3, result.Count);
			for(int i = 0 ; i < instructions.Length ; i++)
			{
				Assert.Equal(instructions[i], result[i].Instruction);
			}
		}

		[Fact]
		public void CanGetSectionFromFileOffset()
		{
			uint rawAddress = 0x00038400;
			uint rawSize = 0x00001E00;
			uint rawAddress2 = 0x0003A201;
			var image = Image.ReadFromFile("TestData/BeaEngine.dll");

			object[,] testData = new object[,]
			{{new ImageOffset(image, rawAddress), ".rdata"},
			{new ImageOffset(image, rawAddress + rawSize - 1), ".rdata"},
			{new ImageOffset(image, rawAddress2 + 1), ".data"},
			{new ImageOffset(image, 0x400), ".text"}};

			for(int i = 0 ; i < testData.GetLength(0) ; i++)
			{
				var offset = (ImageOffset)testData[i, 0];
				var section = (String)testData[i, 1];
				var actualSection = offset.GetSection();
				if(section == null)
					Assert.Null(actualSection);
				else
					Assert.Equal(section, actualSection.Name);
			}
		}
		[Fact]
		public void CanGetSectionFromRVA()
		{
			var image = Image.ReadFromFile("TestData/BeaEngine.dll");

			uint virtualAddress = 0x00039000;
			uint virtualSize = 0x00001D47;
			uint rawAddress2 = 0x0003B001;
			object[,] testData = new object[,]
			{{new RVA(virtualAddress), ".rdata"},
			{new RVA(virtualAddress + virtualSize - 1), ".rdata"},
			{new RVA(rawAddress2 + 1), ".data"},
			{new RVA(0x0001000), ".text"}};

			for(int i = 0 ; i < testData.GetLength(0) ; i++)
			{
				var offset = (RVA)testData[i, 0];
				var section = (String)testData[i, 1];
				var actualSection = image.GetSectionAt(offset);
				if(section == null)
					Assert.Null(actualSection);
				else
					Assert.Equal(section, actualSection.Name);
			}
		}

		[Fact]
		public void CanDetectFileOffsetIsRawOnly()
		{
			var image = Image.ReadFromFile("TestData/BeaEngine.dll");
			uint dataSection = 0x0003B000;
			uint virtualSize = 0x00002578;
			var offset = new ImageOffset(image, dataSection + virtualSize);
			try
			{
				offset.ToRVA();
				Assert.True(false, "Should have thrown an exception");
			}
			catch
			{

			}
			new ImageOffset(image, dataSection + virtualSize - 1).ToRVA();
		}

		[Fact]
		public void SimpleCrackMeReturnDifferentCodeWhenResolved()
		{
			var result = StartAndGetReturnCode(SimpleCrackMe);
			Assert.Equal(0, result);
			result = StartAndGetReturnCode(SimpleCrackMe, "one two");
			Assert.Equal(1, result);
		}

		private int StartAndGetReturnCode(string file, string args = null)
		{
			var proc = System.Diagnostics.Process.Start(new FileInfo(file).FullName, args);
			proc.WaitForExit();
			return proc.ExitCode;
		}

		[Fact]
		public void CanStartDebugOnNewProcess()
		{
			using(var dbg = new ProcessDebugger())
			{
				dbg.Start(SimpleCrackMe);
				var debugEvent = dbg.Wait.NextEvent();
				Assert.Equal(DebugEventType.CreateProcessEvent, debugEvent.EventType);
				debugEvent = dbg.Continue.Until(DebugEventType.ExitProcessEvent);
				Assert.Equal(DebugEventType.ExitProcessEvent, debugEvent.EventType);
			}
		}

		[Fact]
		public void CanDebugProcessToEndAndGetExitCode()
		{
			using(var dbg = new ProcessDebugger())
			{
				dbg.Start(SimpleCrackMe);
				var returnCode = dbg.Continue.ToEnd();
				Assert.NotNull(dbg.ExitCode);
				Assert.Equal(0, dbg.ExitCode.Value);
				Assert.Equal(returnCode, dbg.ExitCode.Value);
			}
		}

		[Fact]
		public static void CanBreakAtEntryThenSkipBreakpointNextStepIn()
		{
			using(var dbg = new ProcessDebugger())
			{
				dbg.Start(SimpleCrackMe);
				Breakpoint breakPoint = dbg.Breakpoints.AtEntryPoint();
				var evt = dbg.BreakingThread.Continue.UntilBreakpoint(breakPoint);
				Assert.NotNull(evt);
				Assert.True(evt.Details.IsFirstChance);
				Assert.True(evt.Details.Exception.Reason == ExceptionReason.ExceptionBreakpoint);
				Assert.Equal(dbg.Debuggee.MainModule.EntryPointAddress, breakPoint.Address.ToIntPtr());
				Assert.Equal(breakPoint.Address.ToIntPtr(), dbg.BreakingThread.ThreadContext.EIP);
				Assert.Equal(dbg.Debuggee.MainModule.EntryPointAddress, evt.Details.Exception.Address);
				var nextEvent = dbg.BreakingThread.Wait.NextEvent(); //Does not throw a trap
				Assert.NotEqual(DebugEventType.ExceptionEvent, nextEvent.EventType);
			}
		}

		[Fact]
		public static void CanStepIn()
		{
			using(var dbg = new ProcessDebugger())
			{
				dbg.Start(SimpleCrackMe);
				Breakpoint breakPoint = dbg.Breakpoints.AtEntryPoint();
				dbg.BreakingThread.Continue.UntilBreakpoint(breakPoint);
				dbg.BreakingThread.StepByStep = true;
				AssertIsSingleStep(dbg.Wait.NextEvent());
				AssertIsSingleStep(dbg.Wait.NextEvent());
			}
		}

		private static void AssertIsSingleStep(DebugEvent evt)
		{
			var exception = evt.As<ExceptionDetail>();
			Assert.NotNull(exception);
			Assert.Equal(ExceptionReason.ExceptionSingleStep, exception.Exception.Reason);
		}
		private static void AssertIsBreakpoint(DebugEvent evt)
		{
			var exception = evt.As<ExceptionDetail>();
			Assert.NotNull(exception);
			Assert.Equal(ExceptionReason.ExceptionBreakpoint, exception.Exception.Reason);
		}
		private static void AssertIsNotSingleStep(DebugEvent evt)
		{
			var exception = evt.As<ExceptionDetail>();
			if(exception == null)
				return;
			Assert.NotEqual(ExceptionReason.ExceptionSingleStep, exception.Exception.Reason);
		}

		[Fact]
		public static void BreakpointDoesNotCancelStepIn()
		{
			using(var dbg = new ProcessDebugger())
			{
				dbg.Start(SimpleCrackMe);
				dbg.Wait.NextEvent();
				dbg.BreakingThread.StepByStep = true;
				Breakpoint breakPoint = dbg.Breakpoints.AtEntryPoint();
				dbg.Continue.UntilBreakpoint(breakPoint);
				var address = dbg.BreakingThread.CurrentInstruction;
				Assert.Equal(breakPoint.Address, address);
				AssertIsSingleStep(dbg.Wait.NextEvent());
				AssertIsSingleStep(dbg.Wait.NextEvent());
				dbg.BreakingThread.StepByStep = false;
				dbg.BreakingThread.GoTo(address);
				AssertIsBreakpoint(dbg.BreakingThread.Wait.NextEvent());
				AssertIsNotSingleStep(dbg.BreakingThread.Wait.NextEvent());
			}
		}

		[Fact]
		public static void ShouldNotCrashIfDetachAtBreakpoint()
		{
			using(var dbg = new ProcessDebugger())
			{
				dbg.Start(SimpleCrackMe);
				dbg.Wait.NextEvent();
				Breakpoint breakPoint = dbg.Breakpoints.AtEntryPoint();
				dbg.BreakingThread.Continue.UntilBreakpoint(breakPoint);
				dbg.BreakingThread.Continue.Run();
			}
		}

		[Fact]
		public static void CanAssemble()
		{
			var testData = new object[,]
			{
				{ new byte[]{ 0xCC } , "INT3", false },
				{ new byte[]{ 0x8B, 0xEC } , "MOV EBP,ESP", true },
				{ new byte[]{ 0x83,0xC4,0x04 } , "ADD ESP,4", true },
				{ new byte[]{ 0x90}, "NOP",false}
			};

			for(int i = 0 ; i < testData.GetLength(0) ; i++)
			{
				var shellCode = (byte[])testData[i, 0];
				var instruction = (string)testData[i, 1];
				var hasMultipleEncoding = (bool)testData[i, 2];
				var actual = DisasmWrapper.Assemble(instruction);
				Assert.Equal(instruction, actual.Instruction);


				//Some command have multiple encoding (http://www.ollydbg.de/srcdescr.htm#_Toc531975951)
				if(!hasMultipleEncoding)
				{
					Assert.Equal(shellCode.Length, actual.Bytes.Length);
					for(int y = 0 ; y < shellCode.Length ; y++)
					{
						Assert.Equal(shellCode[y], actual.Bytes[y]);
					}
				}
			}

			try
			{
				DisasmWrapper.Assemble("Hello");
				Assert.False(true, "Should have thrown on bad instruction");
			}
			catch(AssemblerException)
			{

			}
		}

		[Fact]
		public void CanPatchAndUnpatch()
		{
			using(var dbg = new ProcessDebugger())
			{
				PatchJNZ(dbg);
				Assert.Equal(1, dbg.Continue.ToEnd());
			}

			using(var dbg = new ProcessDebugger())
			{
				PatchJNZ(dbg).Undo();
				Assert.Equal(0, dbg.Continue.ToEnd());
			}
			using(var dbg = new ProcessDebugger())
			{
				var patch = PatchJNZ(dbg);
				patch.Undo();
				patch.Redo();
				Assert.Equal(1, dbg.Continue.ToEnd());
			}
		}

		private Patch PatchJNZ(ProcessDebugger dbg)
		{
			dbg.Start(SimpleCrackMe);
			RVA mainRVA = dbg.SymbolManager.FromName("SimpleCrackMe.exe", "main").RVA; //new RVA(0x113D0);
			RVA jnzRVA = new RVA(0x113F2);  // mainRVA + 0x22;
			dbg.Wait.NextEvent();
			Breakpoint breakPoint = dbg.Breakpoints.At("SimpleCrackMe.exe", mainRVA);
			dbg.BreakingThread.Continue.UntilBreakpoint(breakPoint);
			var disasm = dbg.BreakingThread.Continue.UntilInstruction("JNZ");
			var expected = dbg.AddressOfModule("SimpleCrackMe.exe") + jnzRVA;
			var actual = dbg.BreakingThread.CurrentInstruction;
			Assert.Equal(expected, actual);
			return dbg.BreakingThread.WriteInstruction("NOP", true);
		}

		[Fact]
		public void CanCrack()
		{
			using(var dbg = new ProcessDebugger())
			{
				PatchJNZ(dbg);
				dbg.Patches.ModifyImage(dbg.Debuggee.MainModule, "SimpleCrackMe-Patched.exe");
				Assert.Equal(1, dbg.Continue.ToEnd()); //Resolved !!!!	
				var result = StartAndGetReturnCode("SimpleCrackMe-Patched.exe");
				Assert.Equal(1, result); //Patched !!!!
			}
		}

		[Fact]
		public void CanGetRVAFromPdbPublicServerOrExport()
		{
			using(var dbg = new ProcessDebugger())
			{
				dbg.Start(SimpleCrackMe);

				var symbol = dbg.SymbolManager.FromName("kernel32.dll", "_GetStdHandle@4");
				Assert.NotNull(symbol);
				Assert.Equal(SymbolType.Pdb, symbol.Type);

				symbol = dbg.SymbolManager.FromName("kernel32.dll", "GetStdHandle");
				Assert.NotNull(symbol);
				Assert.Equal(SymbolType.Export, symbol.Type);
			}
		}
	}
}

