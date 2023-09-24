#include "core.hpp"
//#include "ecdsa_shit/key.h"

/*
* TASKS:
* +	1. API https://www.blockchain.com to get balance
* +	2. Multithreading on CPU
* 	3. Multithreading on GPU
*/

std::ofstream _out_file;
std::atomic<size_t> _wallets_worked{ 0 };
std::atomic<int> _availableThreads{ 0 };
std::vector<std::thread> _threads;
std::mutex _lock;

BOOL WINAPI consoleHandler(DWORD signal)
{
	if (signal == CTRL_C_EVENT)
	{
		std::cout << "\nExit caught\n";
		if (_out_file.is_open())
			_out_file.close();
		std::cout << "wallets.txt is saved\n";
		std::cout << _wallets_worked << " : wallets were checked\n";
		Sleep(2000);
		exit(0);
	}
	return true;
}

void walletCalculate(std::vector<uint8_t>&& HASHES)
{
	ecdsa::Key key(HASHES);
	core::holder::keysHolder t1(key.getPublicKey(),
		key.getPrivateKey());
	std::vector<uint8_t>& bitcoinWallet = t1.getBitcoinAddress();
	core::lstrip('\0', bitcoinWallet);
	std::string wallet(bitcoinWallet.begin(), bitcoinWallet.end());
	std::stringstream ss;
	//std::cout << "balance: ";
	core::BlockChainParser::getHTML(wallet, ss);
	size_t balance;
	try
	{
		ss >> balance;
	}
	catch (const std::exception& ex)
	{
		std::cout << ex.what() << std::endl;
	}
	//std::cout << balance << std::endl;
	if (balance)
	{
		std::cout << wallet << '\n' << balance << " satoshi\n\n";
		std::vector<char> hexstring;
		core::HEX(t1.movePrivateKey(), hexstring);
		_lock.lock();
		core::dumpWallet(bitcoinWallet, hexstring, _out_file);
		_lock.unlock();
	}
	_wallets_worked.fetch_add(1);
	_availableThreads.fetch_add(1);
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
	std::string seedStr;
	std::cin >> seedStr;
	std::stringstream ss(seedStr);
	ss >> seed;
	time_t initial_seed = time(NULL);
	initial_seed ^= seed;
	std::cout << "Initial seed: " << initial_seed << std::endl;

	int threadsNum = 1;
	std::cout << "Enter threads number: ";
	std::cin >> threadsNum;
	_availableThreads = threadsNum;
	_threads.resize(threadsNum);

	std::vector<uint8_t> HASHES(PRIVATE_KEY_SIZE);

	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, (char*)(&initial_seed), sizeof(time_t));
	SHA256_Update(&sha256, ecdsa::HASHSALT, 16);
	SHA256_Final(&HASHES.front(), &sha256);
	int k = 0;

	_out_file.open("wallets.txt");

	while (1)
	{
		if (_availableThreads.load(std::memory_order_relaxed))
		{
			_availableThreads.fetch_sub(1);
			SHA256_Update(&sha256, &HASHES.front(), 32);

			std::thread thr(walletCalculate, HASHES);
			thr.detach();
			//walletCalculate(std::move(HASHES));

			SHA256_Update(&sha256, ecdsa::HASHSALT, 16);
			HASHES.clear();
			HASHES.resize(32);
			SHA256_Final(&HASHES.front(), &sha256);
		}
	}
	return 0;
}
