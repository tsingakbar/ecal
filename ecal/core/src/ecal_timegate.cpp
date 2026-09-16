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

#include <ecal/ecal.h>
#include <ecal/ecal_os.h>

#include "ecal_timegate.h"

#include <chrono>
#include <thread>
#include <string.h>

namespace eCAL
{
  //////////////////////////////////////////////////////////////////
  // CTimeGate
  //////////////////////////////////////////////////////////////////
  std::atomic<bool> CTimeGate::m_created;

  CTimeGate::CTimeGate()
  {
  };

  CTimeGate::~CTimeGate()
  {
    Destroy();
  }

  void CTimeGate::Create()
  {
    if(m_created) return;
    m_created = true;
  }

  void CTimeGate::Destroy()
  {
    if(!m_created) return;
    m_created = false;
  }

  std::string CTimeGate::GetName()
  {
    if (!m_created) return("");
    return("ecaltime-localtime");
  }

  long long CTimeGate::GetMicroSeconds()
  {
    if (!m_created) return(0);
    return(GetNanoSeconds() / 1000);
  }

  long long CTimeGate::GetNanoSeconds()
  {
    if (!m_created) return(0);
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
  }

  bool CTimeGate::SetNanoSeconds(long long /*time_*/)
  {
    // localtime is not master-settable
    return(false);
  }

  bool CTimeGate::IsSynchronized()
  {
    if (!m_created) return(false);
    return(true);
  }

  bool CTimeGate::IsMaster()
  {
    if (!m_created) return(false);
    return(true);
  }

  void CTimeGate::SleepForNanoseconds(long long duration_nsecs_)
  {
    if (!m_created) return;
    std::this_thread::sleep_for(std::chrono::nanoseconds(duration_nsecs_));
  }

  void CTimeGate::GetStatus(int& error_, std::string* const status_message_)
  {
    if (!m_created)
    {
      error_ = -1;
      if (status_message_) {
        status_message_->assign("eCAL Timegate has not been created.");
      }
    }
    else
    {
      error_ = 0;
      if (status_message_) {
        status_message_->assign("everything is fine.");
      }
    }
  }

  bool CTimeGate::IsValid()
  {
    int error(0);
    GetStatus(error, nullptr);
    return (error >= 0);
  }
};
