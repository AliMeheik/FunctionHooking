#include <windows.h>

#define HOOK_LENGTH 5

struct _Args {
    const wchar_t* message;
    const wchar_t* title;
    BYTE orgBytes[ HOOK_LENGTH ];
    PBYTE targetAddress;
    PBYTE customAddress;
};

_Args args;

void BeginHook( PVOID targetAddress, PVOID customAddress, BYTE hookLength ) {

    BYTE hookPattern[] = {
        0xE9,0x90,0x90,0x90,0x90
    };

    uintptr_t jmpAddress = ( args.customAddress - args.targetAddress ) - 5;

    *reinterpret_cast< DWORD* >( &hookPattern[ 1 ] ) = jmpAddress;

    DWORD oldProtection;
    VirtualProtect( targetAddress, hookLength, PAGE_EXECUTE_READWRITE, &oldProtection );

    memcpy( args.orgBytes, args.targetAddress, HOOK_LENGTH );
    memcpy( targetAddress, hookPattern, sizeof( hookPattern ) );

    DWORD newProtection;
    VirtualProtect( targetAddress, hookLength, oldProtection, &newProtection );

}


int WINAPI CustomMessageBox( HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uiType ) {

    DWORD oldProtection;

    VirtualProtect( args.targetAddress, HOOK_LENGTH, PAGE_EXECUTE_READWRITE, &oldProtection );

    memcpy( args.targetAddress, args.orgBytes, HOOK_LENGTH );

    DWORD newProtection;
    VirtualProtect( args.targetAddress, HOOK_LENGTH, oldProtection, &newProtection );

    int retValue = MessageBoxW( NULL, L"This is now my msg box", lpCaption, MB_ICONEXCLAMATION );

    BeginHook( args.targetAddress, args.customAddress, HOOK_LENGTH );

    return retValue;
}


DWORD __stdcall Start( LPVOID param ) {

    uintptr_t targetAddress = 0;
    HMODULE kernel32Address = nullptr;

    kernel32Address = GetModuleHandle( L"user32.dll" );
    args.targetAddress = reinterpret_cast< PBYTE >( GetProcAddress( kernel32Address, "MessageBoxW" ) );
    args.customAddress = reinterpret_cast< PBYTE >( CustomMessageBox );

    BeginHook( args.targetAddress, args.customAddress, HOOK_LENGTH );
    MessageBoxW( NULL, L"Hi", L"MyOriginalTextBox", MB_ICONEXCLAMATION );
    return TRUE;
}



BOOL WINAPI DllMain( HANDLE hDLL, DWORD Reason, LPVOID Reserved ) {

    switch( Reason ) {
    case DLL_PROCESS_ATTACH:
    {
        HANDLE inThreadHandle = CreateThread( NULL, NULL, Start, hDLL, NULL, NULL );
        CloseHandle( inThreadHandle ); break;
    }
    }
    return TRUE;
}
