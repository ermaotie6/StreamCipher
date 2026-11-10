#include <catch2/catch_test_macros.hpp>
#include "streamcipher/stream/pipeline.hpp"
#include "streamcipher/stream/stream.hpp"
#include <array>
#include <fstream>
#include <random>
#include <stdexcept>
#include <vector>

using namespace streamcipher;
namespace fs = std::filesystem;
namespace {
const std::array<uint8_t,16> key{};
const std::array<uint8_t,12> nonce{};
struct Files {
    fs::path root;
    Files() {
        std::random_device rng;
        for (int i=0;i<100;++i) {
            auto candidate=fs::temp_directory_path()/("scipher-test-"+std::to_string(rng()));
            if(fs::create_directory(candidate)) { root=candidate; return; }
        }
        throw std::runtime_error("Cannot create test directory");
    }
    ~Files() { std::error_code ec; fs::remove_all(root,ec); }
    fs::path path(const char* name) const { return root/name; }
    void write(const char* name, const std::vector<uint8_t>& data) {
        std::ofstream out(path(name),std::ios::binary);
        out.exceptions(std::ios::failbit|std::ios::badbit);
        if(!data.empty()) out.write(reinterpret_cast<const char*>(data.data()),data.size());
        out.close();
    }
    std::vector<uint8_t> read(const char* name) {
        std::ifstream in(path(name),std::ios::binary);
        if(!in) throw std::runtime_error("Missing output");
        return {std::istreambuf_iterator<char>(in),{}};
    }
    void no_staging() {
        for(const auto& entry:fs::directory_iterator(root))
            REQUIRE(entry.path().filename().string().find(".scipher-")!=0);
    }
};
}

TEST_CASE("File output matches one-shot for empty and uneven chunks", "[pipeline]") {
    Files f;
    for(auto mode:{cipher::Mode::CTR,cipher::Mode::GCM}) {
        pipeline::FilePipeline pipe(cipher::Algorithm::AES_128,mode,key,nonce);
        for(size_t size:{size_t(0),size_t(1),size_t(15),size_t(16),size_t(17),size_t(257)}) {
            std::vector<uint8_t> plain(size);
            for(size_t i=0;i<size;++i) plain[i]=static_cast<uint8_t>(i);
            f.write("in",plain);
            std::vector<uint8_t> expected(size+(mode==cipher::Mode::GCM?16:0));
            stream::encrypt_one_shot(cipher::Algorithm::AES_128,mode,plain,expected,key,nonce);
            for(size_t step:{size_t(0),size_t(1),size_t(17),size_t(64)}) {
                pipeline::PipelineConfig config; config.chunk_size=step;
                uint64_t last=0; size_t calls=0;
                config.on_progress=[&](uint64_t done,uint64_t total){
                    REQUIRE(total==size); REQUIRE(done>=last); REQUIRE(done<=total);
                    last=done; ++calls;
                };
                REQUIRE(pipe.encrypt_file(f.path("in"),f.path("encrypted"),config)==expected.size());
                REQUIRE(f.read("encrypted")==expected);
                REQUIRE(calls>0); REQUIRE(last==size);
                calls=0;last=0;
                REQUIRE(pipe.decrypt_file(f.path("encrypted"),f.path("out"),config)==size);
                REQUIRE(f.read("out")==plain);
                REQUIRE(calls>0); REQUIRE(last==size);
            }
        }
    }
    f.no_staging();
}

TEST_CASE("File authentication failure preserves destination and removes staging", "[pipeline]") {
    Files f;
    pipeline::FilePipeline pipe(cipher::Algorithm::AES_128,cipher::Mode::GCM,key,nonce);
    f.write("in",std::vector<uint8_t>(33,0x42));
    REQUIRE(pipe.encrypt_file(f.path("in"),f.path("encrypted"))==49);
    const auto encrypted=f.read("encrypted");
    const std::vector<uint8_t> saved{1,2,3};
    for(size_t index:{size_t(0),size_t(32),size_t(33),size_t(48)}) {
        auto bad=encrypted;bad[index]^=1;f.write("bad",bad);
        f.write("out",saved);
        REQUIRE_THROWS(pipe.decrypt_file(f.path("bad"),f.path("out")));
        REQUIRE(f.read("out")==saved);
        REQUIRE_THROWS(pipe.decrypt_file(f.path("bad"),f.path("absent")));
        REQUIRE_FALSE(fs::exists(f.path("absent")));
        f.no_staging();
    }
    for(size_t size:{size_t(0),size_t(1),size_t(15),size_t(16),size_t(48)}) {
        f.write("bad",std::vector<uint8_t>(encrypted.begin(),encrypted.begin()+size));
        REQUIRE_THROWS(pipe.decrypt_file(f.path("bad"),f.path("out")));
        REQUIRE(f.read("out")==saved);
    }
}

TEST_CASE("File aliases and I/O errors never truncate existing data", "[pipeline]") {
    Files f;
    const std::vector<uint8_t> saved{1,2,3,4,5};
    f.write("in",saved);f.write("out",saved);
    pipeline::FilePipeline pipe(cipher::Algorithm::AES_128,cipher::Mode::CTR,key,nonce);
    REQUIRE_THROWS(pipe.encrypt_file(f.path("missing"),f.path("out")));
    REQUIRE(f.read("out")==saved);
    REQUIRE_THROWS(pipe.encrypt_file(f.path("in"),f.path("in")));
    REQUIRE(f.read("in")==saved);
    fs::create_hard_link(f.path("in"),f.path("alias"));
    REQUIRE_THROWS(pipe.encrypt_file(f.path("in"),f.path("alias")));
    REQUIRE(f.read("in")==saved);
    REQUIRE_THROWS(pipe.encrypt_file(f.path("in"),f.path("missing/out")));
    fs::create_directory(f.path("directory"));
    REQUIRE_THROWS(pipe.encrypt_file(f.path("in"),f.path("directory")));
    REQUIRE(fs::is_directory(f.path("directory")));
    pipeline::PipelineConfig config;config.chunk_size=1;
    config.on_progress=[](uint64_t,uint64_t){throw std::runtime_error("cancel");};
    REQUIRE_THROWS(pipe.encrypt_file(f.path("in"),f.path("out"),config));
    REQUIRE(f.read("out")==saved);
    config.on_progress={};config.parallel=true;
    REQUIRE_THROWS(pipe.encrypt_file(f.path("in"),f.path("out"),config));
    REQUIRE(f.read("out")==saved);
    f.no_staging();
}

TEST_CASE("File progress precedence and moved-from pipeline", "[pipeline]") {
    Files f;f.write("in",{1,2,3});
    pipeline::FilePipeline pipe(cipher::Algorithm::AES_128,cipher::Mode::CTR,key,nonce);
    size_t fallback=0,configured=0;
    pipe.on_progress([&](uint64_t,uint64_t){++fallback;});
    REQUIRE(pipe.encrypt_file(f.path("in"),f.path("out"))==3);
    REQUIRE(fallback==1);
    pipeline::PipelineConfig config;
    config.on_progress=[&](uint64_t,uint64_t){++configured;};
    REQUIRE(pipe.encrypt_file(f.path("in"),f.path("out"),config)==3);
    REQUIRE(fallback==1);REQUIRE(configured==1);
    auto moved=std::move(pipe);
    REQUIRE_THROWS_AS(pipe.encrypt_file(f.path("in"),f.path("out")),std::logic_error);
    REQUIRE_THROWS_AS(pipe.on_progress({}),std::logic_error);
    REQUIRE(moved.encrypt_file(f.path("in"),f.path("out"))==3);
}

TEST_CASE("Progress callback is a stable snapshot and reentry cannot corrupt a run", "[pipeline]") {
    Files f; f.write("in", {1,2,3,4}); f.write("out", {9});
    pipeline::FilePipeline pipe(cipher::Algorithm::AES_128, cipher::Mode::GCM, key, nonce);
    pipeline::PipelineConfig config; config.chunk_size = 1;
    size_t original = 0, replacement = 0;
    config.on_progress = [&](uint64_t, uint64_t) {
        ++original;
        config.on_progress = [&](uint64_t, uint64_t) { ++replacement; };
        config.chunk_size = 100;
        REQUIRE_THROWS_AS(pipe.encrypt_file(f.path("in"), f.path("recursive")), std::logic_error);
    };
    REQUIRE(pipe.encrypt_file(f.path("in"), f.path("out"), config) == 20);
    REQUIRE(original == 4); REQUIRE(replacement == 0);
    REQUIRE_FALSE(fs::exists(f.path("recursive")));
    REQUIRE(pipe.encrypt_file(f.path("in"), f.path("out"), config) == 20);
    REQUIRE(replacement == 1);
    pipe.on_progress([&](uint64_t, uint64_t) { ++original; pipe.on_progress({}); });
    config.chunk_size = 1; config.on_progress = {};
    REQUIRE(pipe.encrypt_file(f.path("in"), f.path("out"), config) == 20);
    REQUIRE(original == 8);
    f.no_staging();
}

TEST_CASE("Callback failure resets run state and input growth rolls back", "[pipeline]") {
    Files f; f.write("in", {1,2,3}); f.write("out", {9});
    pipeline::FilePipeline pipe(cipher::Algorithm::AES_128, cipher::Mode::CTR, key, nonce);
    pipeline::PipelineConfig config; config.chunk_size = 1;
    config.on_progress = [](uint64_t, uint64_t) { throw std::runtime_error("stop"); };
    REQUIRE_THROWS(pipe.encrypt_file(f.path("in"), f.path("out"), config));
    REQUIRE(f.read("out") == std::vector<uint8_t>{9});
    config.on_progress = [&](uint64_t done, uint64_t) {
        if (done == 1) { std::ofstream append(f.path("in"), std::ios::binary | std::ios::app); append.put('x'); }
    };
    REQUIRE_THROWS(pipe.encrypt_file(f.path("in"), f.path("out"), config));
    REQUIRE(f.read("out") == std::vector<uint8_t>{9});
    config.on_progress = {};
    REQUIRE(pipe.encrypt_file(f.path("in"), f.path("out"), config) == 4);
    f.no_staging();
}
