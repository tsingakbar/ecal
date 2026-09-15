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

#include <iostream>
#include <list>
#include <string>

#ifdef __linux__
#include <csignal>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "ecal/ecal_process.h"
#include "../include/zombie_instance_killer.h"

bool ZombieInstanceKiller::KillZombieInstance(const std::list<std::string>& process_names)
{
  bool ret_val = false;
  if (!process_names.empty())
  {
    for (const auto& pid_name : process_names)
    {
      ret_val = KillZombie(pid_name);
    }
  }

  return ret_val;
}


#ifdef __linux__
bool ZombieInstanceKiller::KillZombie(const std::string& pid_name)
{
  bool return_value = false;

  std::string command = "pidof " + pid_name;
  FILE* pipe = popen(command.c_str(), "r");

  if (pipe != nullptr)
  {
    char buf[512];
    if (fgets(buf, 512, pipe) == nullptr) return false;

    std::list<std::string> pids;
    char* pch;
    pch = strtok(buf, " ");
    while (pch != nullptr)
    {
      pids.push_back(pch);
      pch = strtok(nullptr, " ");
    }

    if (!pids.empty())
    {
      for (const auto& pid : pids)
      {
        pid_t current_pid = strtoul(pid.c_str(), nullptr, 10);

        if ((current_pid != 0) && (current_pid != getpid()))
        {
          std::string result_str = eCAL::Process::StopProcess(current_pid) ? "SUCCESS: " : "FAIL: ";

          std::cout << result_str << "Terminating the process with PID : " << current_pid << std::endl;

          return_value = true;
        }
      }
    }
    pclose(pipe);
  }

  return return_value;
}
#endif
