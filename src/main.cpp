#include <assert.h>
#include <cstdio>
#include <string>
#include <filesystem>

#include "cryptopp/secblock.h"
#include "cryptopp/chacha.h"
#include "cryptopp/hex.h"
#include "cryptopp/osrng.h"
#include "cryptopp/files.h"

// generate files of this size
// unsure if file size affects the bug's frequency
const size_t FILES_SIZE = 1024 * 1024; // 1MB files

// generate this many files per run
const uint32_t FILES_PER_RUN = 100;

// run the test this many times
// each run's output will be buffered to a file named with its sha
// all runs' shas will be concatenated for a final check at the end of all runs
const uint32_t TOTAL_RUNS = 50;

// generate a file full of random garbage for fuzzing
bool MakeFile(const std::filesystem::path& filepath, size_t size_in_bytes) {
    // call rand() until the file is full
    std::ofstream fout(filepath.c_str(), std::ios::binary);
    if (!fout) {
        return false;
    }

    const size_t BUFSIZE = 4096;
    char buf[BUFSIZE];
    while (size_in_bytes) {
        // fill it up
        for (size_t i = 0; i < BUFSIZE / 4; i++) {
            int r = rand() * 1023181;
            std::memcpy(buf + (i * 4), &r, 4);
        }
        // and flush
        // this will write some extra content past the end if size_in_bytes isn't a multiple of 4096
        // and that's fine, the point is to get a file full of garbage, the exact size doesn't matter
        fout.write(buf, BUFSIZE);
        size_in_bytes = size_in_bytes > BUFSIZE ? size_in_bytes - BUFSIZE : 0;
    }

    fout.close();
    return true;
}

// calculate sha256 of a file, return the hex-encoded sha256
std::string ShaFile(const std::filesystem::path& filepath) {
    CryptoPP::SHA256 sha;
    std::string digest;
    CryptoPP::FileSource fsource(filepath.c_str(), true,
        new CryptoPP::HashFilter(sha,
            new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest))
        )
    );
    return digest;
}

// calculate sha256 of a string, return the hex-encoded sha256
std::string ShaString(const std::string& in) {
    std::string digest;
    CryptoPP::SHA256 sha;
    CryptoPP::StringSource ssource(in, true,
        new CryptoPP::HashFilter(sha,
            new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest))
        )
    );
    return digest;
}

std::string BlockToHex(const CryptoPP::SecByteBlock& block) {
    std::string digest;
    CryptoPP::StringSource ssource(block.data(), block.size(), true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(digest)
        )
    );
    return digest;
}

CryptoPP::SecByteBlock HexToBlock (std::string hexstr) {
    CryptoPP::SecByteBlock block(hexstr.length() / 2);
    CryptoPP::StringSource ssource(hexstr, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::ArraySink(&block[0], block.size())
        )
    );
    return block;
}

// cha cha encrypt a file to <filepath>.enc
void CryptFile(const std::filesystem::path& filepath, const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& nonce) {
    CryptoPP::ChaCha::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());
    std::string fpath_out = filepath.string() + ".enc";

    CryptoPP::FileSource fs = CryptoPP::FileSource(
        filepath.c_str(), true, 
        new CryptoPP::StreamTransformationFilter(
            enc, new CryptoPP::FileSink(
                fpath_out.c_str(), true
            )
        )
    );
}

CryptoPP::SecByteBlock RandBlock(size_t size) {
    assert(size % 4 == 0);
    CryptoPP::SecByteBlock block(size);
    for (size_t i = 0; i < size / 4; i++) {
        int r = rand() * 982797;
        std::memcpy(block.begin() + i * 4, &r, 4);
    }
    return block;
}

// run one iteration of the fuzz test using the iter number as a seed
std::stringstream DoFuzzRun(uint32_t iter) {
    // explicitly re-seed rand() for each test set
    srand(iter);

    // make a directory for each run
    std::string dirstr;
    {
        std::stringstream dir_ss;
        dir_ss << "run_" << iter;
        dirstr = dir_ss.str();
        std::error_code ec;
        std::filesystem::create_directory(dirstr, ec);
    }

    // feed the concatenated output of each run to this stream 
    std::stringstream run_ss;
    run_ss << "run " << iter << ":\n\n";

    // run the test for each file
    for (uint32_t i = 0; i < FILES_PER_RUN; i++) {
        std::stringstream filename;
        filename << dirstr << "/run_" << iter << "_file_" << i << ".bin";
        std::filesystem::path filepath(filename.str());

        // first make the file
        bool made = MakeFile(filepath, FILES_SIZE);
        assert(made);

        // then sha it
        std::string sha = ShaFile(filepath);

        // then encrypt it, the encrypted filepath will add .enc to the filename
        const CryptoPP::SecByteBlock key = RandBlock(32);
        const CryptoPP::SecByteBlock nonce = RandBlock(8);
        CryptFile(filepath, key, nonce);

        // then sha the encrypted file
        filename << ".enc";
        std::string encsha = ShaFile(filename.str());

        std::string hex_key = BlockToHex(key);
        std::string hex_nonce = BlockToHex(nonce);

        // and add the output to the stringstream
        run_ss << "file " << i << ":\n"
            << "- sha: " << sha << "\n"
            << "- enc: " << encsha << "\n"
            << "- key: " << hex_key << "\n"
            << "- non: " << hex_nonce << "\n\n";
    }

    return run_ss;
}

// the original fuzz test that was used to find a key/nonce/file combo that causes the issue
// iter_offset is used for srand(), you can keep incrementing it until an encrypted sha mismatch is found
void RunFuzzTest(uint32_t iter_offset) {
    // this stringstream will concatenate the sha256's from each run's output
    // then IT will be sha'd at the end of the run
    // if the encrypted shas of all files are the same, then the final sha will match across machines/runs
    std::stringstream shas_ss;

    // iterate each run
    // each run re-seeds rand()
    for (uint32_t i = 0; i < TOTAL_RUNS; i++) {
        std::stringstream run_ss = DoFuzzRun(i + iter_offset);

        // get the sha256 of this run
        std::string run_str = run_ss.str();
        std::string run_sha = ShaString(run_str);
        shas_ss << run_sha;

        printf("%s----------------------------------------\n\n", run_str.c_str());
    }

    std::string shas_str = shas_ss.str();
    // the sha256 of the all the other concatenated sha256's
    std::string final_sha = ShaString(shas_str);

    printf("\n\n\nFINAL SHA: %s\n", final_sha.c_str());

}

int main() {
    // minimal test case:
    // run 459 file 76 is a known mismatch with this key and nonce
    const CryptoPP::SecByteBlock key = HexToBlock("D5B9750A22880B92F1A47BE26CB594F166903B5FC1D79EB99F384AAA356B78D9");
    const CryptoPP::SecByteBlock nonce = HexToBlock("3A205D07536CD3CC");
    std::filesystem::path filepath("run_459_file_76.bin");

    std::string sha = ShaFile(filepath);
    CryptFile(filepath, key, nonce);
    std::string encsha = ShaFile(filepath.string() + ".enc");

    printf("sha256: %s\nencsha: %s", sha.c_str(), encsha.c_str());



    // uncomment to run the fuzz test that helped find the issue
    // note that it makes a lot of little files (you can change the parameters at the top of this file)
    // TODO the offset for srand() could be a CLI arg instead of hard-coded
    // RunFuzzTest(450);



    return 0;
}