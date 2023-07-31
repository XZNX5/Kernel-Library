#pragma once
#include "module_getter.hpp"

namespace impl
{
	inline bool scan_for_pattern_code_helper( const uint8_t* data, const uint8_t* signature, const char* mask )
	{
		if ( !MmIsAddressValid( const_cast< uint8_t* >( data ) ) )
			return false;

		for ( ; *mask; ++mask, ++data, ++signature )
			if ( *mask == 'x' && *data != *signature )
				return false;

		return true;
	}

	uint8_t* scan_for_pattern_code( const nt::rtl_module_info module, const char* signature, const char* signature_mask )
	{
		if ( !module )
			return nullptr;

		const auto module_start = reinterpret_cast< uint8_t* >( module.image_base );
		const auto module_size = module_start + module.image_size;

		/* iterate the entire module */
		for ( auto segment = module_start; segment < module_size; segment++ )
		{
			if ( scan_for_pattern_code_helper( segment, reinterpret_cast< uint8_t* >( const_cast< char* >( signature ) ), signature_mask ) )
				return segment;
		}

		return nullptr;
	}
}
