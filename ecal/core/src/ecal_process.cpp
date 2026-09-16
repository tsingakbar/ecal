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
* @brief  eCAL process interface
**/

#include <ecal/ecal.h>
#include <ecal/ecal_config.h>

#include "ecal_def.h"
#include "ecal_config_reader_hlp.h"
#include "ecal_registration_provider.h"
#include "ecal_registration_receiver.h"
#include "ecal_globals.h"
#include "ecal_process.h"

#include <array>
#include <chrono>
#include <thread>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <memory>
#include <fstream>

#include "sys_usage.h"

#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <cstring>
#include <atomic>

#ifdef ECAL_OS_LINUX
#include <spawn.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/select.h>
#include <limits.h>
#include <netinet/in.h>

#include <ecal_utils/ecal_utils.h>

#endif /* ECAL_OS_LINUX */

#include <ecal_utils/command_line.h>

#ifndef NDEBUG
#define STD_COUT_DEBUG( x ) { std::stringstream ss; ss << x; std::cout << ss.str(); }
#else
#define STD_COUT_DEBUG( x )
#endif

namespace
{
  std::string GetBufferStr(int size)
  {
    std::string unit = "byte";
    if (size > 1024)
    {
      size /= 1024;
      unit = "kByte";
    }
    if (size > 1024)
    {
      size /= 1024;
      unit = "MByte";
    }
    return std::to_string(size) + " " + unit;
  }

  std::string LayerMode(int mode)
  {
    switch (mode)
    {
    case 0:
      return "off";
      break;
    case 1:
      return "on";
      break;
    case 2:
      return "auto";
      break;
    }
    return "???";
  }
  std::pair<bool, int> get_host_id()
  {
    return std::make_pair(true, static_cast<int>(gethostid()));
  }
}

namespace eCAL
{
  namespace Process
  {
    void DumpConfig()
    {
      std::string cfg;
      DumpConfig(cfg);
      std::cout << cfg;
    }

    void DumpConfig(std::string& cfg_s_)
    {
      std::stringstream sstream;
      sstream << "------------------------- SYSTEM ---------------------------------" << std::endl;
      sstream << "Version                  : " << ECAL_VERSION << " (" << ECAL_DATE << ")" << std::endl;
#ifdef ECAL_OS_LINUX
      sstream << "Platform                 : linux" << std::endl;
#endif
      sstream << std::endl;

      if (!eCAL::IsInitialized())
      {
        sstream << "Components               : NOT INITIALIZED ( call eCAL::Initialize() )";
        sstream << std::endl;
        cfg_s_ = sstream.str();
        return;
      }

      sstream << "------------------------- CONFIGURATION --------------------------" << std::endl;
      sstream << "Default INI              : " << g_default_ini_file << std::endl; // WARNING: The eCAL Recorder relies on the identifier "Default INI" to obtain the ecal.ini path (It parses the output of this function)
      sstream << std::endl;

      sstream << "------------------------- NETWORK --------------------------------" << std::endl;
      sstream << "Host name                : " << Process::GetHostName() << std::endl;

      if (Config::IsNetworkEnabled())
      {
        sstream << "Network mode             : cloud" << std::endl;
      }
      else
      {
        sstream << "Network mode             : local" << std::endl;
      }
      sstream << "Network ttl              : " << Config::GetUdpMulticastTtl() << std::endl;
      sstream << "Network sndbuf           : " << GetBufferStr(Config::GetUdpMulticastSndBufSizeBytes()) << std::endl;
      sstream << "Network rcvbuf           : " << GetBufferStr(Config::GetUdpMulticastRcvBufSizeBytes()) << std::endl;
      sstream << "Multicast group          : " << Config::GetUdpMulticastGroup() << std::endl;
      sstream << "Multicast mask           : " << Config::GetUdpMulticastMask() << std::endl;
      int port = Config::GetUdpMulticastPort();
      sstream << "Multicast ports          : " << port << " - " << port + 10 << std::endl;
      auto bandwidth = Config::GetMaxUdpBandwidthBytesPerSecond();
      if (bandwidth < 0)
      {
        sstream << "Bandwidth limit (udp)    : not limited" << std::endl;
      }
      else
      {
        sstream << "Bandwidth limit udp      : " << GetBufferStr(bandwidth) + "/s" << std::endl;
      }
      sstream << std::endl;

      sstream << "------------------------- TIME -----------------------------------" << std::endl;
      sstream << "Synchronization realtime : " << Config::GetTimesyncModuleName() << std::endl;
      sstream << "Synchronization replay   : " << eCALPAR(TIME, SYNC_MOD_REPLAY) << std::endl;
      sstream << "State                    : ";
      if (g_timegate()->IsSynchronized()) sstream << " synchronized " << std::endl;
      else                                sstream << " not synchronized " << std::endl;
      sstream << "Master / Slave           : ";
      if (g_timegate()->IsMaster())       sstream << " Master " << std::endl;
      else                                sstream << " Slave " << std::endl;
      int         status_state;
      std::string status_msg;
      g_timegate()->GetStatus(status_state, &status_msg);
      sstream << "Status (Code)            : \"" << status_msg << "\" (" << status_state << ")" << std::endl;
      sstream << std::endl;

      sstream << "------------------------- PUBLISHER LAYER DEFAULTS ---------------"       << std::endl;
      sstream << "Layer Mode INPROC        : " << LayerMode(Config::GetPublisherInprocMode())  << std::endl;
      auto zero_copy = Config::IsMemfileZerocopyEnabled();

      if (zero_copy)
      {
        sstream << "Layer Mode SHM (ZEROCPY) : " << LayerMode(Config::GetPublisherShmMode()) << std::endl;
      }
      else
      {
        sstream << "Layer Mode SHM           : " << LayerMode(Config::GetPublisherShmMode()) << std::endl;
      }
      sstream << "Layer Mode TCP           : " << LayerMode(Config::GetPublisherTcpMode()) << std::endl;
      sstream << "Layer Mode UDP MC        : " << LayerMode(Config::GetPublisherUdpMulticastMode()) << std::endl;
      sstream << std::endl;

      sstream << "------------------------- SUBSCRIPTION LAYER DEFAULTS ------------"               << std::endl;
      sstream << "Layer Mode INPROC        : " << LayerMode(Config::IsInprocRecEnabled())  << std::endl;
      sstream << "Layer Mode SHM           : " << LayerMode(Config::IsShmRecEnabled())     << std::endl;
      sstream << "Layer Mode TCP           : " << LayerMode(Config::IsTcpRecEnabled())  << std::endl;
      sstream << "Layer Mode UDP MC        : " << LayerMode(Config::IsUdpMulticastRecEnabled())  << std::endl;


      // write it into std:string
      cfg_s_ = sstream.str();
    }

    std::string GetHostName()
    {
      if (g_host_name.empty())
      {
        char hname[1024] = { 0 };
        if (gethostname(hname, 1024) == 0)
        {
          g_host_name = hname;
        }
        else
        {
          std::cerr << "Unable to get host name" << std::endl;
        }
      }
      return(g_host_name);
    }

    int GetHostID()
    {
      return internal::GetHostID();
    }

    namespace internal
    {
      int GetHostID()
      {
        if (g_host_id == 0)
        {
          // try to get unique host id
          bool success(false);
          int  id(0);
          std::tie(success, id) = get_host_id();
          if (success)
          {
            g_host_id = id;
          }
          // never try again to not waste time
          else
          {
            g_host_id = -1;
            std::cerr << "Unable to get host id" << std::endl;
          }
        }
        return(g_host_id);
      }
    }

    std::string GetUnitName()
    {
      return(g_unit_name);
    }

    std::string GetTaskParameter(const char* sep_)
    {
      std::string par_line;
      for (auto par : g_task_parameter)
      {
        if (!par_line.empty()) par_line += sep_;
        par_line += par;
      }
      return(par_line);
    }

    void SleepMS(const long time_ms_)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(time_ms_));
    }

    void SleepNS(const long long time_ns_)
    {
        std::this_thread::sleep_for(std::chrono::nanoseconds(time_ns_));
    }

    float GetProcessCpuUsage()
    {
      return(GetCPULoad() * 100.0f);
    }

    long long GetSClock()
    {
      return(GetWClock());
    };

    long long GetSBytes()
    {
      return(GetWBytes());
    };

    long long GetWClock()
    {
      return(g_process_wclock);
    };

    long long GetWBytes()
    {
      return(g_process_wbytes);
    };

    long long GetRClock()
    {
      return(g_process_rclock);
    };

    long long GetRBytes()
    {
      return(g_process_rbytes);
    };

    void SetState(eCAL_Process_eSeverity severity_, eCAL_Process_eSeverity_Level level_, const char* info_)
    {
      g_process_severity = severity_;
      g_process_severity_level = level_;
      if (info_ != nullptr)
      {
        g_process_info = info_;
      }
    }

    int AddRegistrationCallback(enum eCAL_Registration_Event event_, RegistrationCallbackT callback_)
    {
      if (!g_registration_receiver()) return -1;
      if (g_registration_receiver()->AddRegistrationCallback(event_, callback_)) return 0;
      return -1;
    }

    int RemRegistrationCallback(enum eCAL_Registration_Event event_)
    {
      if (!g_registration_receiver()) return -1;
      if (g_registration_receiver()->RemRegistrationCallback(event_)) return 0;
      return -1;
    }
  }
}




#ifdef ECAL_OS_LINUX

extern char **environ;

namespace
{
  void create_proc_id()
  {
    if (eCAL::g_process_id == 0)
    {
      eCAL::g_process_id   = getpid();
      eCAL::g_process_id_s = std::to_string(eCAL::g_process_id);
    }
  }

  int parseLine(char* line)
  {
    int i = strlen(line);
    while (*line < '0' || *line > '9') line++;
    line[i - 3] = '\0';
    i = atoi(line);
    return i;
  }
}


namespace eCAL
{
  namespace Process
  {
    int GetProcessID()
    {
      create_proc_id();
      return(g_process_id);
    }

    std::string GetProcessIDAsString()
    {
      create_proc_id();
      return(g_process_id_s);
    }

    /**
    * @brief Returns the fully qualified path for the current process's binary
    *
    * @return the process path
    */
    std::string GetProcessName()
    {
      if (g_process_name.empty()) {
        // Read the link to our own executable
        char buf[PATH_MAX] = { 0 };
        ssize_t length = readlink("/proc/self/exe", buf, PATH_MAX);

        if (length < 0)
        {
          std::cerr << "Unable to get process name: " << strerror(errno) << std::endl;
          return "";
        }
        // Copy the binary name to a std::string
        g_process_name = std::string(buf, length);

      }
      return g_process_name;
    }
    std::string GetProcessParameter()
    {
      if (g_process_par.empty())
      {

        const std::string filename = "/proc/self/cmdline";
        std::vector<std::string> argument_vector;

        std::ifstream cmdline_file(filename, std::ios::binary);
        if (!cmdline_file.is_open())
        {
          std::cerr << "Failed to open " << filename << '\n';
          return "";
        }
        else
        {
          std::string arg;
          while (std::getline(cmdline_file, arg, '\0')) // the cmdline contains arguments separated by \0
          {
            argument_vector.emplace_back(arg);
          }
        }

        size_t complete_char_num(0);
        for (std::string& argument : argument_vector)
        {
          std::string escaped_arg;
          escaped_arg.reserve(argument.size() + 2);

          bool constains_space = (argument.find(' ') != std::string::npos);

          // Escape special characters
          if (constains_space) escaped_arg += '\"';
          for (char c : argument)
          {
            if (c == '\\')                              // Escape [\]
              escaped_arg += "\\\\";
            else if (c == '\"')                         // Escape ["]
              escaped_arg += "\\\"";
            else if (c == '\'')                         // Escape [']
              escaped_arg += "\\\'";
            else
              escaped_arg += c;
          }
          if (constains_space) escaped_arg += '\"';

          if(escaped_arg.empty())
            escaped_arg = "\"\"";

          complete_char_num += escaped_arg.size();
          argument = escaped_arg;
        }

        std::string process_par;
        process_par.reserve(complete_char_num + argument_vector.size());

        for (auto arg_it = argument_vector.begin(); arg_it != argument_vector.end(); arg_it++)
        {
          if (arg_it != argument_vector.begin())
            process_par += ' ';
          process_par += *arg_it;
        }

        g_process_par = process_par;
      }
      return(g_process_par);
    }

    unsigned long GetProcessMemory()
    {
      FILE* file = fopen("/proc/self/status", "r");
      if (file == nullptr) return(0);

      int result = 0;
      char line[128] = { 0 };
      while (fgets(line, 128, file) != nullptr)
      {
        if (strncmp(line, "VmSize:", 7) == 0)
        {
          result = parseLine(line);
          break;
        }
      }
      fclose(file);
      return(result * 1024);
    }
  }
}

#endif /* ECAL_OS_LINUX */

#undef STD_COUT_DEBUG
