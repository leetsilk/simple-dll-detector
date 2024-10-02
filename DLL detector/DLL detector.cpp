#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <memory>
#include <array>

class DllScanner {
public:
    DllScanner( ) = default;

    bool query_process_for_target_dll( const TCHAR* dll_name, DWORD process_id ) {
        HANDLE hModuleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id );
        if ( hModuleSnap == INVALID_HANDLE_VALUE ) {
            return false;
        }

        MODULEENTRY32 me32;
        me32.dwSize = sizeof( MODULEENTRY32 );

        bool found = false;
        if ( Module32First( hModuleSnap, &me32 ) ) {
            do {
                if ( _tcsicmp( me32.szModule, dll_name ) == 0 ) {
                    found = true;
                    break;
                }
            } while ( Module32Next( hModuleSnap, &me32 ) );
        }

        CloseHandle( hModuleSnap );
        return found;
    }

    void query_suspicious_dlls( const TCHAR* dll_name ) {
        HANDLE hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
        if ( hProcessSnap == INVALID_HANDLE_VALUE ) {
            return;
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof( PROCESSENTRY32 );

        if ( !Process32First( hProcessSnap, &pe32 ) ) {
            CloseHandle( hProcessSnap );
            return;
        }

        do {
            if ( query_process_for_target_dll( dll_name, pe32.th32ProcessID ) ) {
                wprintf( L"Detected module %s in process -> %s [ PID: %lu ]\n", dll_name, pe32.szExeFile, pe32.th32ProcessID );
            }
        } while ( Process32Next( hProcessSnap, &pe32 ) );

        CloseHandle( hProcessSnap );
    }

    void scan_for_blacklisted_dlls( const std::array<const TCHAR*, 5>& blacklisted_dlls ) {
        for ( const auto& dll : blacklisted_dlls ) {
            query_suspicious_dlls( dll );
        }
    }
};

inline auto dll_scanner = std::make_unique<DllScanner>( );

int main( ) {

    /*enter more modules below that you would like to scan for in the system*/

    std::array<const TCHAR*, 5> blacklisted_dlls = { 
        L"CorperfmonExt.dll", 
        L"perfdisk.dll", 
        L"perfnet.dll", 
        L"perfos.dll", 
        L"perfmib.dll" 
    };

    dll_scanner->scan_for_blacklisted_dlls( blacklisted_dlls );

    return std::cin.get( ) != EOF;
}