#include <iostream>
#include <windows.h>

uintptr_t shipPtr_address = 0x3374;
uintptr_t doDamage_offset = 0x104A;
uintptr_t targetAddress = 0;

BOOL Hook( void* targetAddress, void* customFuncAddress, int hookLength ) {

    DWORD oldProtection;
    VirtualProtect( targetAddress, hookLength, PAGE_EXECUTE_READWRITE, &oldProtection );

    memset( targetAddress, 0x90, hookLength ); //clear bytes

    uintptr_t relativeAddress = reinterpret_cast< uintptr_t >( customFuncAddress ) - reinterpret_cast< uintptr_t > ( targetAddress ) - 5;

    *( BYTE* )targetAddress = 0xE9;
    *( uintptr_t* )( reinterpret_cast< uintptr_t >( targetAddress ) + 1 ) = relativeAddress;

    DWORD newProtection;
    VirtualProtect( targetAddress, hookLength, oldProtection, &newProtection );
    return TRUE;
}

uintptr_t continueAddress;

void __declspec( naked ) customFunction() {

    void* currentShipAddress;

    __asm {
        mov ecx, 0Ah
        pushfd
        pushad
        mov currentShipAddress, esi
    }

    if( currentShipAddress != reinterpret_cast< void* >( targetAddress ) ) {
        _asm {
            popad
            popfd
            jmp continueAddress
        }
    }

    __asm {
        popad
        popfd
        pop esi
        retn
    }
}

DWORD WINAPI Start( LPVOID param ) {

    uintptr_t baseAddress = reinterpret_cast< uintptr_t >( GetModuleHandle( NULL ) );
    uintptr_t ptrAddress = baseAddress + shipPtr_address;
    targetAddress = *reinterpret_cast< uintptr_t* >( ptrAddress );
    uintptr_t doDamageAddress = baseAddress + doDamage_offset;
    int hookLength = 5;  //total amount of bytes overwritten commands occupy
    continueAddress = doDamageAddress + hookLength;
    Hook( ( LPVOID )doDamageAddress, ( LPVOID )customFunction, hookLength );
    return TRUE;
}

BOOL WINAPI DllMain( HANDLE hDLL, DWORD Reason, LPVOID Reserved ) {

    switch( Reason ) {
    case DLL_PROCESS_ATTACH:
        HANDLE in_Thead =
            CreateThread( 0, 0, ( LPTHREAD_START_ROUTINE )Start, hDLL, 0, 0 );
    }

    return TRUE;
}
