#include "ecdsa.h"

namespace ecdsa
{
	Key::Key()
	{
		private_key_data.resize(PRIVATE_KEY_SIZE);
		time_t start = time(NULL);
		SHA256_CTX sha256;
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, (char*)(&start), sizeof(time_t));
		SHA256_Update(&sha256, HASHSALT, 16);
		SHA256_Final(&private_key_data.front(), &sha256);
		ctx_ = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
		if (!verifyKey())
			throw std::exception("Invalid private key!");
		calculatePublicKey(true);
		
	}

	Key::Key(std::vector<uint8_t>& key_data)
	{
		ctx_ = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
		private_key_data = std::move(key_data);
		if (!verifyKey())
			throw std::exception("Invalid private key!");
		calculatePublicKey(true);
	}

	Key::~Key()
	{
		if (ctx_)
		{
			secp256k1_context_destroy(ctx_);
			ctx_ = nullptr;
		}
	}

	bool Key::verifyKey()
	{
		return secp256k1_ec_seckey_verify(ctx_, private_key_data.data());
	}

	bool Key::calculatePublicKey(bool compressed)
	{	
		secp256k1_pubkey public_key;
		int ret = secp256k1_ec_pubkey_create(ctx_, &public_key, private_key_data.data());
		if (ret != 1)
			return false;
		size_t out_size = PUBLIC_KEY_SIZE;
		public_key_data.resize(PUBLIC_KEY_SIZE);
		secp256k1_ec_pubkey_serialize(
			ctx_, public_key_data.data(), &out_size, &public_key,
			compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
		public_key_data.resize(out_size);
		return true;
	}

	std::vector<uint8_t> Key::getPublicKey()
	{
		return std::move(public_key_data);
	}

	std::vector<uint8_t> Key::getPrivateKey()
	{
		return std::move(private_key_data);
	}

}