#pragma once
#include "memory_scanner_code.hpp"
#include "memory_utility.hpp"

namespace impl
{
	extern "C" NTSYSAPI PCHAR NTAPI PsGetProcessImageFileName( PEPROCESS );

	PEPROCESS nt_find_process( const char* wanted_process_name )
	{
		const auto ntoskrnl = nt_find_module("ntoskrnl.exe");

		static const auto relative_sig = scan_for_pattern_code( ntoskrnl, "\x79\xdc\xe9", "xxx" );

		if ( !relative_sig )
			return nullptr;
		
		static const auto PsGetNextProcess = resolve_call< PEPROCESS( * )( PEPROCESS )>( resolve_jxx( relative_sig ) );

		static const auto EtwpIsProcessZombie = reinterpret_cast< bool( * )( PEPROCESS )>( scan_for_pattern_code(ntoskrnl, "\x8B\x81\x00\x00\x00\x00\xA8\x04\x75\x00\x33\xC0", "xx????xxx?xx"));

		if ( !PsGetNextProcess || !EtwpIsProcessZombie)
			return nullptr;

		PEPROCESS previous_process = PsGetNextProcess( nullptr );

		while ( previous_process )
		{
			if ( !EtwpIsProcessZombie(previous_process) && ( std::strcmp( wanted_process_name, PsGetProcessImageFileName( previous_process ) ) == 0 ) )
				return previous_process;

			previous_process = PsGetNextProcess( previous_process );
		}

		return nullptr;
	}
}
