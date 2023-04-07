#include "uniq_id_generator.h"

#include <unistd.h>

#include <atomic>
#include <array>
#include <chrono>
#include <climits>
#include <random>

namespace
{
    // uniqueness is guaranteed across processes within same PID namespace,
    // and most likely unique across containers and even hosts.
    class SimpleUniqIdGenerator
    {
    public:
        SimpleUniqIdGenerator() : hostname_hash_(GetHostnameHash()), pid_(GetPid())
        {
            std::random_device rand_dev;
            std::mt19937 engine(rand_dev());
            std::uniform_int_distribution<uint32_t> rand_dist(0, std::numeric_limits<uint32_t>::max()); // 闭区间
            incrementer_.store(rand_dist(engine));
        }

        // collision across container/host is possible but unlikely
        uint64_t Generate()
        {
            // host(16bit) + pid(24bit) + incrementer(24bit)
            return (hostname_hash_ << (24 + 24)) | ((pid_ << 24) & 0x0000ffffff000000) |
                   (incrementer_.fetch_add(1) & 0x0000000000ffffff);
        }

    private:
        static uint64_t GetHostnameHash()
        {
            std::array<char, HOST_NAME_MAX> hostname_buffer;
            if (0 == ::gethostname(hostname_buffer.data(), hostname_buffer.size()))
            {
                return std::hash<std::string>{}(std::string(hostname_buffer.data()));
            }
            // most of the time gethostid() is just a int32_t composed by 127.0.0.1
            return ::gethostid();
        }

        static uint32_t GetPid()
        {
#if 0
    // what if running in docker container without --pid=host
    std::ifstream if_cpuset_info("/proc/self/cpuset");
    if (if_cpuset_info.good()) {
      std::string cpuset_info((std::istreambuf_iterator<char>(if_cpuset_info)), std::istreambuf_iterator<char>());
    }
#endif
            return ::getpid();
        }

    private:
        const uint64_t hostname_hash_;
        const uint64_t pid_; // 64-bit linux max pid use only 22 bit
        std::atomic<uint32_t> incrementer_;
    };
}

namespace eCAL
{
    uint64_t GenerateUniqIdWithinPidNamespace()
    {
        static SimpleUniqIdGenerator gen;
        return gen.Generate();
    }

}