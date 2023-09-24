#pragma once

#ifndef CORE_H
#define CORE_H

#include "includes.h"
#include "ecdsa/ecdsa.h"
#include <fstream>
#include <Windows.h>

#include <curlpp/Easy.hpp>
#include <curlpp/cURLpp.hpp>
#include <curlpp/Options.hpp>

//---------------------------------
#ifdef _WIN64

#endif
//---------------------------------
//---------------------------------
#ifdef __linux__

#endif
//---------------------------------
//---------------------------------
#ifdef __APPLE__

#endif
//---------------------------------
#define HEX4BITSTOINT(a) (((a) >= 'a') ? (a - 'a' + 10) : (a - '0'))

const std::string BLOCKCHAIN_DOMAIN = "https://blockchain.info/q/addressbalance/";

namespace core
{
	const char hex_digits[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
	const char base58chars[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

	void HEX(std::vector<uint8_t>& digits, std::vector<char>& dest);
	void fromHEX(std::vector<char>& hex, std::vector<uint8_t>& dest);

	void lstrip(const char symbol, std::vector<uint8_t>& source);

	namespace BlockChainParser
	{
		void getHTML(std::string& bitcoin_wallet, std::stringstream& response);
	}

	namespace holder
	{
		class keysHolder
		{
		public:
			keysHolder(std::vector<uint8_t> publicKey,
				std::vector<uint8_t> privateKey);
			~keysHolder();

			std::vector<uint8_t>& getBitcoinAddress();
			std::vector<uint8_t>& getPublicKey();
			std::vector<uint8_t>& getPrivateKey();

			std::vector<uint8_t> movePublicKey();
			std::vector<uint8_t> movePrivateKey();

		private:
			std::vector<uint8_t> bitcoin_addr;
			std::vector<uint8_t> public_key_data;
			std::vector<uint8_t> private_key_data;
		};

	}


}
#endif // !CORE_H
/*
0345171286d48c5899b4634d966c35f486f311e2621bc5dabb9af601d8c8c06a26
02da75625220a9f4f0e4eb61a69885167b2e2c3da0b65daa866ec04311b58261b4
031e7bcc70c72770dbb72fea022e8a6d07f814d2ebe4de9ae3f7af75bf706902a7
*/