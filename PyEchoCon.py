import threading
from _winapi import GENERIC_READ, OPEN_EXISTING, GENERIC_WRITE
from ctypes import Structure, byref, sizeof, POINTER, windll, c_void_p, c_char_p, c_size_t, wintypes, HRESULT, \
    create_string_buffer
from ctypes.wintypes import *
from time import sleep

null_ptr = POINTER(c_void_p)()

FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002

FILE_ATTRIBUTE_NORMAL = 128

STD_ERROR_HANDLE = -12
STD_INPUT_HANDLE = -10
STD_OUTPUT_HANDLE = -11

INVALID_HANDLE_VALUE = -1

S_OK = 0

EXTENDED_STARTUPINFO_PRESENT = 0x00080000
PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016

ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004

STARTF_USESTDHANDLES = 256

PVOID = LPVOID
PULONG = c_void_p
LPTSTR = c_void_p
LPBYTE = c_char_p
SIZE_T = c_size_t

HPCON = HANDLE


def _errcheck_bool(value, func, args):
    if not value:
        raise ctypes.WinError()
    return args


# BOOL WINAPI CreatePipe(
#   _Out_    PHANDLE               hReadPipe,
#   _Out_    PHANDLE               hWritePipe,
#   _In_opt_ LPSECURITY_ATTRIBUTES lpPipeAttributes,
#   _In_     DWORD                 nSize
# );
CreatePipe = windll.kernel32.CreatePipe
CreatePipe.argtype = [POINTER(HANDLE), POINTER(HANDLE), PVOID, DWORD]
CreatePipe.restype = BOOL
CreatePipe.errcheck = _errcheck_bool

# DWORD WINAPI GetLastError(void);
GetLastError = windll.kernel32.GetLastError
GetLastError.argtype = []
GetLastError.restype = DWORD

# void WINAPI SetLastError(
#   _In_ DWORD dwErrCode
# );
SetLastError = windll.kernel32.SetLastError
SetLastError.argtype = [DWORD]

# BOOL WINAPI GetConsoleMode(
#   _In_  HANDLE  hConsoleHandle,
#   _Out_ LPDWORD lpMode
# );
GetConsoleMode = windll.kernel32.GetConsoleMode
GetConsoleMode.argtype = [HANDLE, LPDWORD]
GetConsoleMode.restype = BOOL
# GetConsoleMode.errcheck = _errcheck_bool

# BOOL WINAPI SetConsoleMode(
#   _In_ HANDLE hConsoleHandle,
#   _In_ DWORD  dwMode
# );
SetConsoleMode = windll.kernel32.SetConsoleMode
SetConsoleMode.argtype = [HANDLE, DWORD]
SetConsoleMode.restype = BOOL
SetConsoleMode.errcheck = _errcheck_bool

# BOOL InitializeProcThreadAttributeList(
#   LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
#   DWORD                        dwAttributeCount,
#   DWORD                        dwFlags,
#   PSIZE_T                      lpSize
# );
InitializeProcThreadAttributeList = windll.kernel32.InitializeProcThreadAttributeList
InitializeProcThreadAttributeList.argtype = [POINTER(HANDLE), POINTER(HANDLE), PVOID, DWORD]
InitializeProcThreadAttributeList.restype = BOOL
InitializeProcThreadAttributeList.errcheck = _errcheck_bool

# BOOL UpdateProcThreadAttribute(
#   LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
#   DWORD                        dwFlags,
#   DWORD_PTR                    Attribute,
#   PVOID                        lpValue,
#   SIZE_T                       cbSize,
#   PVOID                        lpPreviousValue,
#   PSIZE_T                      lpReturnSize
# );
UpdateProcThreadAttribute = windll.kernel32.UpdateProcThreadAttribute
UpdateProcThreadAttribute.argtype = [
    POINTER(PVOID),
    DWORD,
    POINTER(DWORD),
    PVOID,
    SIZE_T,
    PVOID,
    POINTER(SIZE_T)
]
UpdateProcThreadAttribute.restype = BOOL
UpdateProcThreadAttribute.errcheck = _errcheck_bool

# void DeleteProcThreadAttributeList(
#   LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList
# );
DeleteProcThreadAttributeList = windll.kernel32.DeleteProcThreadAttributeList
DeleteProcThreadAttributeList.argtype = [
    POINTER(PVOID),
]

# HANDLE CreateFileW(
#   LPCWSTR               lpFileName,
#   DWORD                 dwDesiredAccess,
#   DWORD                 dwShareMode,
#   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
#   DWORD                 dwCreationDisposition,
#   DWORD                 dwFlagsAndAttributes,
#   HANDLE                hTemplateFile
# );
CreateFileW = windll.kernel32.CreateFileW # <-- Unicode version!
CreateFileW.restype = HANDLE
CreateFileW.argtype = [
    LPCWSTR,
    DWORD,
    DWORD,
    POINTER(c_void_p),
    DWORD,
    DWORD,
    HANDLE
]

# BOOL CreateProcessW(
#   LPCWSTR               lpApplicationName,
#   LPWSTR                lpCommandLine,
#   LPSECURITY_ATTRIBUTES lpProcessAttributes,
#   LPSECURITY_ATTRIBUTES lpThreadAttributes,
#   BOOL                  bInheritHandles,
#   DWORD                 dwCreationFlags,
#   LPVOID                lpEnvironment,
#   LPCWSTR               lpCurrentDirectory,
#   LPSTARTUPINFOW        lpStartupInfo,
#   LPPROCESS_INFORMATION lpProcessInformation
# );
CreateProcessW = windll.kernel32.CreateProcessW # <-- Unicode version!
CreateProcessW.restype = BOOL
CreateProcessW.errcheck = _errcheck_bool

# typedef struct _COORD {
#   SHORT X;
#   SHORT Y;
# } COORD, *PCOORD;
class COORD(Structure):
    _fields_ = [("X", SHORT),
                ("Y", SHORT)]

class STARTUPINFO(Structure):
    """Create the STARTUPINFO structure."""
    _fields_ = [("cb", DWORD),
                ("lpReserved", LPTSTR),
                ("lpDesktop", LPTSTR),
                ("lpTitle", LPTSTR),
                ("dwX", DWORD),
                ("dwY", DWORD),
                ("dwXSize", DWORD),
                ("dwYSize", DWORD),
                ("dwXCountChars", DWORD),
                ("dwYCountChars", DWORD),
                ("dwFillAttribute", DWORD),
                ("dwFlags", DWORD),
                ("wShowWindow", WORD),
                ("cbReserved2", WORD),
                ("lpReserved2", LPBYTE),
                ("hStdInput", HANDLE),
                ("hStdOutput", HANDLE),
                ("hStdError", HANDLE)]


class STARTUPINFOEX(Structure):
    """Create the STARTUPINFOEX structure."""
    _fields_ = [("StartupInfo", STARTUPINFO),
                ("lpAttributeList", POINTER(PVOID))
                ]

class PROCESS_INFORMATION(Structure):
    """Create the PROCESS_INFORMATION structure."""
    _fields_ = [("hProcess", HANDLE),
                ("hThread", HANDLE),
                ("dwProcessId", DWORD),
                ("dwThreadId", DWORD)]

# DECLSPEC_ALLOCATOR LPVOID HeapAlloc(
#   HANDLE hHeap,
#   DWORD  dwFlags,
#   SIZE_T dwBytes
# );
HeapAlloc = windll.kernel32.HeapAlloc
HeapAlloc.restype = LPVOID
HeapAlloc.argtypes = [HANDLE, DWORD, SIZE_T]

# BOOL HeapFree(
#   HANDLE                 hHeap,
#   DWORD                  dwFlags,
#   _Frees_ptr_opt_ LPVOID lpMem
# );
HeapFree = windll.kernel32.HeapFree
HeapFree.restype = BOOL
HeapFree.argtypes = [HANDLE, DWORD, LPVOID]
HeapFree.errcheck = _errcheck_bool

# HANDLE GetProcessHeap(
#
# );
GetProcessHeap = windll.kernel32.GetProcessHeap
GetProcessHeap.restype = HANDLE
GetProcessHeap.argtypes = []

# HRESULT WINAPI CreatePseudoConsole(
#     _In_ COORD size,
#     _In_ HANDLE hInput,
#     _In_ HANDLE hOutput,
#     _In_ DWORD dwFlags,
#     _Out_ HPCON* phPC
# );
CreatePseudoConsole = windll.kernel32.CreatePseudoConsole
CreatePseudoConsole.argtype = [COORD, HANDLE, HANDLE, DWORD, POINTER(HPCON)]
CreatePseudoConsole.restype = HRESULT


# BOOL ReadFile(
#   HANDLE       hFile,
#   LPVOID       lpBuffer,
#   DWORD        nNumberOfBytesToRead,
#   LPDWORD      lpNumberOfBytesRead,
#   LPOVERLAPPED lpOverlapped
# );

ReadFile = ctypes.windll.kernel32.ReadFile
ReadFile.restype = ctypes.wintypes.BOOL
ReadFile.errcheck = _errcheck_bool
ReadFile.argtypes = (
    HANDLE,  # hObject
    LPVOID,
    DWORD,
    LPDWORD,
    POINTER(c_void_p)
)

# BOOL WriteFile(
#   HANDLE       hFile,
#   LPCVOID      lpBuffer,
#   DWORD        nNumberOfBytesToWrite,
#   LPDWORD      lpNumberOfBytesWritten,
#   LPOVERLAPPED lpOverlapped
# );
WriteFile = ctypes.windll.kernel32.WriteFile
WriteFile.restype = ctypes.wintypes.BOOL
WriteFile.errcheck = _errcheck_bool
WriteFile.argtypes = (
    HANDLE,
    LPCVOID,
    DWORD,
    LPDWORD,
    POINTER(c_void_p)
)

# void WINAPI ClosePseudoConsole(
#     _In_ HPCON hPC
# );
ClosePseudoConsole = windll.kernel32.ClosePseudoConsole
ClosePseudoConsole.argtype = [HPCON]

# BOOL WINAPI CancelIoEx(
#   _In_     HANDLE       hFile,
#   _In_opt_ LPOVERLAPPED lpOverlapped
# );
CancelIoEx = ctypes.windll.kernel32.CancelIoEx
CancelIoEx.restype = ctypes.wintypes.BOOL
CancelIoEx.errcheck = _errcheck_bool
CancelIoEx.argtypes = (
    HANDLE,  # hObject
    POINTER(c_void_p) # lpOverlapped
)

# BOOL CloseHandle(
#   HANDLE hObject
# );
CloseHandle = ctypes.windll.kernel32.CloseHandle
CloseHandle.argtypes = (
    HANDLE,  # hObject
)
CloseHandle.restype = ctypes.wintypes.BOOL
CloseHandle.errcheck = _errcheck_bool


# BOOL WINAPI PeekNamedPipe(
#   _In_      HANDLE  hNamedPipe,
#   _Out_opt_ LPVOID  lpBuffer,
#   _In_      DWORD   nBufferSize,
#   _Out_opt_ LPDWORD lpBytesRead,
#   _Out_opt_ LPDWORD lpTotalBytesAvail,
#   _Out_opt_ LPDWORD lpBytesLeftThisMessage
# );
PeekNamedPipe = ctypes.windll.kernel32.PeekNamedPipe
PeekNamedPipe.restype = ctypes.wintypes.BOOL
PeekNamedPipe.errcheck = _errcheck_bool
PeekNamedPipe.argtypes = (
    ctypes.wintypes.HANDLE,  # hObject
    LPVOID,
    DWORD,
    LPDWORD,
    LPDWORD,
    LPDWORD
)

# DWORD WaitForSingleObject(
#   HANDLE hHandle,
#   DWORD  dwMilliseconds
# );
WaitForSingleObject = ctypes.windll.kernel32.WaitForSingleObject
WaitForSingleObject.restype = ctypes.wintypes.DWORD
WaitForSingleObject.argtypes = (
    ctypes.wintypes.HANDLE,
    DWORD
)

# HRESULT WINAPI ResizePseudoConsole(
#     _In_ HPCON hPC ,
#     _In_ COORD size
# );
ResizePseudoConsole = windll.kernel32.ResizePseudoConsole
ResizePseudoConsole.argtype = [HPCON, COORD]
ResizePseudoConsole.restype = HRESULT

# HANDLE WINAPI GetStdHandle(
#   _In_ DWORD nStdHandle
# );
GetStdHandle = windll.kernel32.GetStdHandle
GetStdHandle.argtype = [DWORD]
GetStdHandle.restype = HANDLE

# typedef struct _CONSOLE_SCREEN_BUFFER_INFO {
#   COORD      dwSize;
#   COORD      dwCursorPosition;
#   WORD       wAttributes;
#   SMALL_RECT srWindow;
#   COORD      dwMaximumWindowSize;
# } CONSOLE_SCREEN_BUFFER_INFO;
class CONSOLE_SCREEN_BUFFER_INFO(Structure):
    """struct in wincon.h."""
    _fields_ = [
        ("dwSize", COORD),
        ("dwCursorPosition", COORD),
        ("wAttributes", WORD),
        ("srWindow", SMALL_RECT),
        ("dwMaximumWindowSize", COORD),
    ]

# BOOL WINAPI GetConsoleScreenBufferInfo(
#   _In_  HANDLE                      hConsoleOutput,
#   _Out_ PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo
# );
GetConsoleScreenBufferInfo = windll.kernel32.GetConsoleScreenBufferInfo
GetConsoleScreenBufferInfo.argtype = [HANDLE, POINTER(CONSOLE_SCREEN_BUFFER_INFO)]
GetConsoleScreenBufferInfo.restype = BOOL
GetConsoleScreenBufferInfo.errcheck = _errcheck_bool

##
##
##

# HRESULT InitializeStartupInfoAttachedToPseudoConsole(STARTUPINFOEX* pStartupInfo, HPCON hPC)

def InitializeStartupInfoAttachedToPseudoConsole(startupInfoEx, hPC):
    dwAttributeCount = 1
    dwFlags = 0
    lpSize = PVOID()

    # Call with null lpAttributeList first to get back the lpSize
    try:
        InitializeProcThreadAttributeList(None,  # _Out_opt_  LPPROC_THREAD_ATTRIBUTE_LIST
                                          dwAttributeCount,  # _In_       DWORD
                                          dwFlags,  # _Reserved_ DWORD
                                          byref(lpSize))  # _Inout_    PSIZE_T
    except WindowsError as e:
        if e.winerror == 122:
            # OSError: [WinError 122] The data area passed to a system call is too small.
            SetLastError(0)
        else:
            raise

    mem = HeapAlloc(GetProcessHeap(), 0, lpSize.value)
    startupInfoEx.lpAttributeList = ctypes.cast(mem, ctypes.POINTER(c_void_p))

    InitializeProcThreadAttributeList(startupInfoEx.lpAttributeList,  # _Out_opt_  LPPROC_THREAD_ATTRIBUTE_LIST
                                      dwAttributeCount,  # _In_       DWORD
                                      dwFlags,  # _Reserved_ DWORD
                                      byref(lpSize))  # _Inout_    PSIZE_T


    UpdateProcThreadAttribute(startupInfoEx.lpAttributeList,  # _Inout_   LPPROC_THREAD_ATTRIBUTE_LIST
                              DWORD(0),
                              DWORD(PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE),  # _In_      DWORD_PTR
                              hPC,          # _In_      PVOID
                              sizeof(hPC),  # _In_      SIZE_T
                              None,         # _Out_opt_ PVOID
                              None,         # _In_opt_  PSIZE_T
                              )

    return mem

# def procreate(hPC):


###
###
###

# HRESULT CreatePseudoConsoleAndPipes(HPCON* phPC, HANDLE* phPipeIn, HANDLE* phPipeOut)
def CreatePseudoConsoleAndPipes(hPC, hPipeIn, hPipeOut):
    # // Create the pipes to which the ConPTY will connect
    hPipePTYIn = wintypes.HANDLE(INVALID_HANDLE_VALUE)
    hPipePTYOut = wintypes.HANDLE(INVALID_HANDLE_VALUE)

    CreatePipe(byref(hPipePTYIn), byref(hPipeOut), None, 0)
    CreatePipe(byref(hPipeIn), byref(hPipePTYOut), None, 0)


    # FIXME: this doesn't work if launched from PyCharm
    # hConsole = GetStdHandle(STD_OUTPUT_HANDLE)
    #     None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)

    # but this works
    hConsole = CreateFileW("CONOUT$", GENERIC_WRITE | GENERIC_READ, FILE_SHARE_WRITE, None,
                          OPEN_EXISTING,0, None)


    consoleMode = DWORD()
    # print("consoleMode", consoleMode)
    GetConsoleMode(hConsole, byref(consoleMode))
    # print("consoleMode", consoleMode)

    SetConsoleMode(hConsole, consoleMode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)

    consoleSize = COORD()
    csbi = CONSOLE_SCREEN_BUFFER_INFO()

    GetConsoleScreenBufferInfo(hConsole, byref(csbi))

    consoleSize.X = csbi.srWindow.Right - csbi.srWindow.Left + 1
    consoleSize.Y = csbi.srWindow.Bottom - csbi.srWindow.Top + 1

    # consoleSize = COORD()
    # consoleSize.X = 80
    # consoleSize.Y = 24
    CreatePseudoConsole(consoleSize, hPipePTYIn, hPipePTYOut, DWORD(0), byref(hPC))

    # dummy invocation, just to see, that function works
    # ResizePseudoConsole(hPC, consoleSize)

    CloseHandle(hPipePTYOut)
    CloseHandle(hPipePTYIn)


def pipeListener(hPipeIn):
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE)

    BUF_SIZE = 512
    lpBuffer = create_string_buffer(BUF_SIZE)

    lpNumberOfBytesRead = DWORD()
    lpBytesWritten = DWORD()

    while True:
        lpNumberOfBytesRead.value = 0
        lpBytesWritten.value = 0

        try:
            ReadFile(hPipeIn, lpBuffer, BUF_SIZE, byref(lpNumberOfBytesRead), null_ptr)
            WriteFile(hConsole, lpBuffer, lpNumberOfBytesRead, lpBytesWritten, null_ptr)
        except WindowsError as e:
            # OSError: [WinError 995] The I/O operation has been aborted because of either a thread exit or an application request.
            if e.winerror == 995:
                return
            else:
                raise

def main():
    szCommand = "ping localhost"

    hPC = HPCON()
    hPipeIn = wintypes.HANDLE(INVALID_HANDLE_VALUE)
    hPipeOut = wintypes.HANDLE(INVALID_HANDLE_VALUE)

    CreatePseudoConsoleAndPipes(hPC, hPipeIn, hPipeOut)

    t3 = threading.Thread(target=lambda: pipeListener(hPipeIn))
    t3.start()

    startupInfoEx = STARTUPINFOEX()
    startupInfoEx.StartupInfo.cb = sizeof(STARTUPINFOEX)

    mem = InitializeStartupInfoAttachedToPseudoConsole(startupInfoEx, hPC)

    lpProcessInformation = PROCESS_INFORMATION()

    CreateProcessW(None,  # _In_opt_      LPCTSTR
                         szCommand,  # _Inout_opt_   LPTSTR
                         None,  # _In_opt_      LPSECURITY_ATTRIBUTES
                         None,  # _In_opt_      LPSECURITY_ATTRIBUTES
                         False,  # _In_          BOOL
                         EXTENDED_STARTUPINFO_PRESENT,  # _In_          DWORD
                         None,  # _In_opt_      LPVOID
                         None,  # _In_opt_      LPCTSTR
                         byref(startupInfoEx.StartupInfo),  # _In_          LPSTARTUPINFO
                         byref(lpProcessInformation))  # _Out_         LPPROCESS_INFORMATION

    WaitForSingleObject(lpProcessInformation.hThread, 10 * 1000)

    sleep(0.5)

    CloseHandle(lpProcessInformation.hThread)
    CloseHandle(lpProcessInformation.hProcess)

    DeleteProcThreadAttributeList(startupInfoEx.lpAttributeList)

    HeapFree(GetProcessHeap(), 0, mem)

    ClosePseudoConsole(hPC)

    CancelIoEx(hPipeIn, null_ptr)

    CloseHandle(hPipeOut)
    CloseHandle(hPipeIn)


if __name__ == '__main__':
    main()
