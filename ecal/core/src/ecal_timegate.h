/* ========================= eCAL LICENSE =================================
 *
 * Copyright (C) 2016 - 2019 Continental Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * ========================= eCAL LICENSE =================================
*/

/**
 * @brief  eCAL time gateway class
**/

#pragma once

#include <ecal/ecal.h>

#include "ecal_global_accessors.h"

#include <atomic>


namespace eCAL
{
  class CTimeGate
  {
  public:
    CTimeGate();
    ~CTimeGate();

    void Create();
    void Destroy();

    std::string GetName();

    long long GetMicroSeconds();
    long long GetNanoSeconds();

    bool SetNanoSeconds(long long time_);

    bool IsSynchronized();
    bool IsMaster();

    void SleepForNanoseconds(long long duration_nsecs_);

    void GetStatus(int& error_, std::string* const status_message_);
    bool IsValid();

  protected:
    static std::atomic<bool> m_created;
  };
};
