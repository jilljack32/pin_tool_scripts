// rip off from stack-debugger.cpp from pin tool examples folder.

#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <cctype>
#include <map>
#include "pin.H"
using std::cerr;
using std::string;
using std::endl;

// Command line switches for this tool.
//
KNOB<ADDRINT> KnobSysCall(KNOB_MODE_WRITEONCE, "pintool",
    "syscall", "0",
    "Stop at specific syscall");


// Virtual register we use to point to each thread's TINFO structure.
//
static REG RegTinfo;


// Information about each thread.
//
struct TINFO
{
    TINFO(ADDRINT base) : _stackBase(base), _max(0), _maxReported(0) {}

    ADDRINT _stackBase;     // Base (highest address) of stack.
    size_t _max;            // Maximum stack usage so far.
    size_t _maxReported;    // Maximum stack usage reported at breakpoint.
    std::ostringstream _os; // Used to format messages.
};

typedef std::map<THREADID, TINFO *> TINFO_MAP;
static TINFO_MAP ThreadInfos;

static std::ostream *Output = &std::cerr;

static VOID OnThreadStart(THREADID, CONTEXT *, INT32, VOID *);
static VOID OnThreadEnd(THREADID, const CONTEXT *, INT32, VOID *);
static VOID Instruction(INS, VOID *);
static VOID Print_Syscall_Number(ADDRINT);
static VOID DoBreakpoint(const CONTEXT *, THREADID);

// flag to track the syscall
// if flag is set we can break on the syscall
bool flag = FALSE;

// save the syscall number in this variable to break into
ADDRINT syscall;

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool can be used to break at specific syscalls" << endl;
    cerr << "pin -t <plugin>.so -syscall <syscall id to break> -- app" << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) return Usage();

    if (PIN_GetDebugStatus() == DEBUG_STATUS_DISABLED)
    {
        std::cerr << "Application level debugging must be enabled to use this tool.\n";
        std::cerr << "Start Pin with either -appdebug or -appdebug_enable.\n";
        std::cerr << std::flush;
        return 1;
    }

    if (!KnobSysCall.Value())
    {
        Usage();
        exit(1);
    }

    if (KnobSysCall.Value())
    {
        syscall = KnobSysCall.Value();
        *Output << "Syscall to track: " << syscall << "\n";
    }

    // Allocate a virtual register that each thread uses to point to its
    // TINFO data.  Threads can use this virtual register to quickly access
    // their own thread-private data.
    //
    RegTinfo = PIN_ClaimToolRegister();
    if (!REG_valid(RegTinfo))
    {
        std::cerr << "Cannot allocate a scratch register.\n";
        std::cerr << std::flush;
        return 1;
    }

    PIN_AddThreadStartFunction(OnThreadStart, 0);
    PIN_AddThreadFiniFunction(OnThreadEnd, 0);
    INS_AddInstrumentFunction(Instruction, 0);

    PIN_StartProgram();
    return 0;
}

static VOID OnThreadStart(THREADID tid, CONTEXT *ctxt, INT32, VOID *)
{
    TINFO *tinfo = new TINFO(PIN_GetContextReg(ctxt, REG_STACK_PTR));
    ThreadInfos.insert(std::make_pair(tid, tinfo));
    PIN_SetContextReg(ctxt, RegTinfo, reinterpret_cast<ADDRINT>(tinfo));
}

static VOID OnThreadEnd(THREADID tid, const CONTEXT *ctxt, INT32, VOID *)
{
    TINFO_MAP::iterator it = ThreadInfos.find(tid);
    if (it != ThreadInfos.end())
    {
        delete it->second;
        ThreadInfos.erase(it);
    }
}

// Initial Instruction instrumentation to find if the instrunction is a syscall
static VOID Instruction(INS ins, VOID *)
{
    if (INS_IsSyscall(ins))
    {
        // if the instruction is a syscall instruction call the callback function Print_Syscall_Number
        // With the argument of the syscall number
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Print_Syscall_Number, IARG_SYSCALL_NUMBER, IARG_END);

        // if the syscall number is the one what we want to track then issue a breakpoint to the remote debugger
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)DoBreakpoint, IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_END);
    }
}

VOID Print_Syscall_Number(ADDRINT num)
{
    *Output << "InserCall Syscall Num: " << num << "\n";

    if (num == syscall)
    {
        flag = TRUE;
    }
}

static VOID DoBreakpoint(const CONTEXT *ctxt, THREADID tid)
{
    if (flag == TRUE)
    {   
        TINFO *tinfo = reinterpret_cast<TINFO *>(PIN_GetContextReg(ctxt, RegTinfo));
        PIN_ApplicationBreakpoint(ctxt, tid, FALSE, tinfo->_os.str());

        // reset flag
        flag = FALSE;
    }
}

