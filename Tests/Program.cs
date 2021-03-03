using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Xunit;
using System.Diagnostics;
using System.Reflection;

namespace Tests
{
	class Program : ITestMethodRunnerCallback
	{
		static void Main(string[] args)
		{
			var env = new MultiAssemblyTestEnvironment();
			env.Load(Assembly.GetExecutingAssembly().Location);
			var methods = env.EnumerateTestMethods();
			env.Run(methods, new Program());
		}


		#region ITestMethodRunnerCallback Members

		public void AssemblyFinished(TestAssembly testAssembly, int total, int failed, int skipped, double time)
		{

		}

		public void AssemblyStart(TestAssembly testAssembly)
		{

		}

		public bool ClassFailed(Xunit.TestClass testClass, string exceptionType, string message, string stackTrace)
		{
			return false;
		}

		public void ExceptionThrown(TestAssembly testAssembly, Exception exception)
		{

		}

		public bool TestFinished(TestMethod testMethod)
		{
			GC.Collect();
			if(testMethod.RunStatus == TestStatus.Passed)
			{
				Console.ForegroundColor = ConsoleColor.Green;
				WriteLine(testMethod.MethodName + " passed");
			}
			if(testMethod.RunStatus == TestStatus.Failed)
			{
				Console.ForegroundColor = ConsoleColor.Red;
				WriteLine(testMethod.MethodName + " failed");
			}
			Console.ForegroundColor = ConsoleColor.White;
			WriteLine(GetLog(testMethod));
			return true;
		}

		private string GetLog(TestMethod testMethod)
		{
			var result = testMethod.RunResults.First();
			if(result is TestPassedResult)
			{
				return ((TestPassedResult)result).Output;
			}
			else if(result is TestFailedResult)
			{
				return ((TestFailedResult)result).Output;
			}
			return "";
		}

		private void WriteLine(string str)
		{
			Console.WriteLine(str);
			Trace.WriteLine(str);
		}

		public bool TestStart(TestMethod testMethod)
		{
			return true;
		}

		#endregion
	}
}
