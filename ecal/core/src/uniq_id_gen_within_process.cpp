#include "uniq_id_gen_within_process.h"

#include <atomic>
#include <chrono>

namespace eCAL
{
    int64_t GenerateUniqIdWithinCurrentProcess()
    {
        static std::atomic<int64_t> ms_unique_id_within_process{0};
        int64_t oldid, newid;
        do
        {
            oldid = ms_unique_id_within_process.load();
            newid = std::chrono::steady_clock::now().time_since_epoch().count();
        } while (!ms_unique_id_within_process.compare_exchange_strong(oldid, newid));
        return newid;
    }
}