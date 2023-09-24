#include "core.hpp"
//#include "ecdsa_shit/key.h"

/*
* TASKS:
* +	1. API https://www.blockchain.com to get balance
* 	2. Multithreading on CPU
* 	3. Multithreading on GPU
*/

std::ofstream* out_file;
size_t wallets_worked = 0;

BOOL WINAPI consoleHandler(DWORD signal)
{
	if (signal == CTRL_C_EVENT)
	{
		std::cout << "\nExit caught\n";
		if (out_file->is_open())
			out_file->close();
		std::cout << "wallets.txt is saved\n";
		std::cout << wallets_worked << " : wallets were checked\n";
		Sleep(2000);
		exit(0);
	}
	return true;
}

void walletCalculate(std::vector<uint8_t>& HASHES, const char semicol[1], const char newline[1])
{
	ecdsa::Key key(HASHES);
	core::holder::keysHolder t1(key.getPublicKey(),
		key.getPrivateKey());
	std::vector<uint8_t>& bitcoinWallet = t1.getBitcoinAddress();
	core::lstrip('\0', bitcoinWallet);
	std::string wallet(bitcoinWallet.begin(), bitcoinWallet.end());
	std::stringstream ss;
	core::BlockChainParser::getHTML(wallet, ss);
	size_t balance;
	ss >> balance;
	if (balance)
	{
		std::cout << wallet << '\n' << balance << "\n\n";
		out_file->write((char*)(&bitcoinWallet.front()), bitcoinWallet.size());
		out_file->write(semicol, 1);
		std::vector<char> hexstring;
		core::HEX(t1.getPrivateKey(), hexstring);
		out_file->write(&hexstring.front(), hexstring.size());
		out_file->write(newline, 1);
	}
	HASHES = t1.movePrivateKey();
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, &HASHES.front(), 32);
	SHA256_Update(&sha256, ecdsa::HASHSALT, 16);
	SHA256_Final(&HASHES.front(), &sha256);
	++wallets_worked;
}

int main()
{
	if (!SetConsoleCtrlHandler(consoleHandler, TRUE))
	{
		std::cout << "\nERROR: Could not set control handler";
		return 1;
	}

	unsigned int seed = 0;
	std::cout << "Enter any 10 digits: ";
	std::cin >> seed;
	time_t initial_seed = time(NULL);
	initial_seed ^= seed;
	std::cout << "Initial seed: " << initial_seed << std::endl;

	std::vector<uint8_t> HASHES(PRIVATE_KEY_SIZE);

	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, (char*)(&initial_seed), sizeof(time_t));
	SHA256_Update(&sha256, ecdsa::HASHSALT, 16);
	SHA256_Final(&HASHES.front(), &sha256);
	int k = 0;

	out_file = new std::ofstream();
	out_file->open("wallets.txt");
	const char semicol[] = { ':' };
	const char newline[] = { '\n' };

	while (1)
	{
		walletCalculate(HASHES, semicol, newline);
	}
	return 0;
}
