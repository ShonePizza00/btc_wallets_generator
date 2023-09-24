#include "core.h"

namespace core
{
	void HEX(std::vector<uint8_t>& digits, std::vector<char>& dest)
	{
		for (uint8_t digit : digits)
		{
			dest.push_back(hex_digits[(digit & 0xf0) >> 4]);
			dest.push_back(hex_digits[(digit & 0x0f)]);
		}
	}

	void fromHEX(std::vector<char>& hex, std::vector<uint8_t>& dest)
	{
		for (int i = 0; i < hex.size(); i += 2)
		{
			uint8_t t1 = 0;
			t1 = HEX4BITSTOINT(hex[i]);
			t1 <<= 4;
			t1 |= HEX4BITSTOINT(hex[i + 1]);
			dest.push_back(t1);
		}
	}

	void lstrip(const char symbol, std::vector<uint8_t>& source)
	{
		if (!source.size())
			return;
		size_t lastIndex = 0;
		for (size_t i = 0; i < source.size(); ++i)
			if (source[i] != symbol)
			{
				lastIndex = i;
				break;
			}
		source.erase(source.begin(), source.begin() + lastIndex);
	}

	namespace BlockChainParser
	{
		using namespace curlpp::options;
		void getHTML(std::string& bitcoin_wallet, std::stringstream& response)
		{
			curlpp::Cleanup myCleanUp;
			curlpp::Easy myRequest;
			myRequest.setOpt<Url>(BLOCKCHAIN_DOMAIN + bitcoin_wallet);
			myRequest.setOpt(new WriteStream(&response));
			myRequest.perform();
		}
	}

	namespace holder
	{
		keysHolder::keysHolder(std::vector<uint8_t> publicKey,
			std::vector<uint8_t> privateKey)
			: public_key_data(std::move(publicKey)),
			private_key_data(std::move(privateKey))
		{
			{
				SHA256_CTX sha256;
				SHA256_Init(&sha256);
				SHA256_Update(&sha256, &public_key_data.front(), public_key_data.size());
				public_key_data.resize(32);
				SHA256_Final(&public_key_data.front(), &sha256);
				RIPEMD160_CTX ripemd;
				RIPEMD160_Init(&ripemd);
				RIPEMD160_Update(&ripemd, &public_key_data.front(), 32);
				public_key_data.resize(21);
				RIPEMD160_Final(&public_key_data.front() + 1, &ripemd);
			}
			public_key_data[0] = 0;
			std::vector<uint8_t> hashsum(32);
			{
				SHA256_CTX sha256;
				SHA256_Init(&sha256);
				SHA256_Update(&sha256, &public_key_data.front(), 21);
				SHA256_Final(&hashsum.front(), &sha256);
				SHA256_Init(&sha256);
				SHA256_Update(&sha256, &hashsum.front(), 32);
				SHA256_Final(&hashsum.front(), &sha256);
			}
			for (int i = 0; i < 4; ++i)
				public_key_data.push_back(hashsum[i]);

			BN_CTX* ctx = BN_CTX_new();
			BIGNUM* num;
			BIGNUM* div;
			BIGNUM* rem;
			BIGNUM* B58;
			num = BN_new();
			div = BN_new();
			rem = BN_new();
			B58 = BN_new();
			BN_bin2bn(&public_key_data.front(), public_key_data.size(), num);
			BN_set_word(B58, 58);
			bitcoin_addr.resize(100);
			int index = 99;
			while (BN_cmp(num, BN_value_one()) > 0) {
				BN_div(div, rem, num, B58, ctx);
				BN_copy(num, div);
				uint64_t r = BN_get_word(rem);
				bitcoin_addr[--index] = base58chars[r];
			}
			bitcoin_addr[--index] = base58chars[BN_get_word(num)];
			BN_free(num);
			BN_free(div);
			BN_free(rem);
			BN_free(B58);
			BN_CTX_free(ctx);
		}

		std::vector<uint8_t>& keysHolder::getBitcoinAddress() //!!!!!!!!
		{
			return bitcoin_addr;
		}

		keysHolder::~keysHolder()
		{

		}

		std::vector<uint8_t>& keysHolder::getPublicKey()
		{
			return public_key_data;
		}

		std::vector<uint8_t>& keysHolder::getPrivateKey()
		{
			return private_key_data;
		}

		std::vector<uint8_t> keysHolder::movePublicKey()
		{
			return std::move(public_key_data);
		}

		std::vector<uint8_t> keysHolder::movePrivateKey()
		{
			return std::move(private_key_data);
		}

	}


}
