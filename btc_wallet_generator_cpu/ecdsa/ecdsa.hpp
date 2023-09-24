#pragma once
#ifndef ECDSA_HPP
#define ECDSA_HPP

#include "../includes.hpp"
#include "secp256k1.h"

#define PUBLIC_KEY_SIZE 65
#define PRIVATE_KEY_SIZE 32

namespace ecdsa
{
	const char* const HASHSALT = { "HASHSALTAZAZAZA" };
	class Key
	{
	public:
		Key();
		//sizeof(key_data) = 128;
		Key(std::vector<uint8_t>& key_data);
		~Key();
		std::vector<uint8_t> getPublicKey();
		std::vector<uint8_t> getPrivateKey();
		bool verifyKey();

	private:
		bool calculatePublicKey(bool compressed);
		secp256k1_context* ctx_ = nullptr;
		std::vector<uint8_t> private_key_data;
		std::vector<uint8_t> public_key_data;
	};
}

#endif // !ECDSA_HPP