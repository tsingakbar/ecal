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
 * @brief  Global monitoring class (implementation)
**/

#include <ecal/ecal.h>
#include <ecal/ecal_config.h>

#include <ecal/ecal_core.h>

#include "ecal_config_reader_hlp.h"
#include "ecal_monitoring_impl.h"

#include "ecal_def.h"

#include <regex>
#include <sstream>

namespace eCAL
{
  ////////////////////////////////////////////////////////
  // local helper
  ////////////////////////////////////////////////////////
  static void GetSampleHost(const eCAL::pb::Sample& ecal_sample_, std::string& host_name_)
  {
    if (ecal_sample_.has_host())
    {
      host_name_ = ecal_sample_.host().hname();
    }
    if (ecal_sample_.has_process())
    {
      host_name_ = ecal_sample_.process().hname();
    }
    if (ecal_sample_.has_service())
    {
      host_name_ = ecal_sample_.service().hname();
    }
    if (ecal_sample_.has_client())
    {
      host_name_ = ecal_sample_.client().hname();
    }
    if (ecal_sample_.has_topic())
    {
      host_name_ = ecal_sample_.topic().hname();
    }
  }

  static bool IsLocalHost(const eCAL::pb::Sample& ecal_sample_)
  {
    std::string host_name;
    GetSampleHost(ecal_sample_, host_name);
    if (host_name.empty())                   return(false);
    if (host_name == Process::GetHostName()) return(true);
    return(false);
  }


  ////////////////////////////////////////
  // Monitoring Implementation
  ////////////////////////////////////////
  CMonitoringImpl::CMonitoringImpl() :
    m_init(false),
    m_network       (Config::IsNetworkEnabled()),
    m_publisher_map (std::chrono::milliseconds(Config::GetMonitoringTimeoutMs())),
    m_subscriber_map(std::chrono::milliseconds(Config::GetMonitoringTimeoutMs())),
    m_process_map   (std::chrono::milliseconds(Config::GetMonitoringTimeoutMs())),
    m_server_map    (std::chrono::milliseconds(Config::GetMonitoringTimeoutMs())),
    m_client_map    (std::chrono::milliseconds(Config::GetMonitoringTimeoutMs()))
  {
  }

  CMonitoringImpl::~CMonitoringImpl()
  {
  }

  void CMonitoringImpl::Create()
  {
    if (m_init) return;

    // network mode
    m_network = Config::IsNetworkEnabled();

    // get name of this host
    m_host_name = Process::GetHostName();

    // start registration receive thread
    CRegistrationReceiveThread::RegMessageCallbackT regmsg_cb = std::bind(&CSampleReceiver::Receive, this, std::placeholders::_1);
    m_reg_rcv_threadcaller = std::make_shared<CRegistrationReceiveThread>(regmsg_cb);

    // start logging receive thread
    CLoggingReceiveThread::LogMessageCallbackT logmsg_cb = std::bind(&CMonitoringImpl::RegisterLogMessage, this, std::placeholders::_1);
    m_log_rcv_threadcaller = std::make_shared<CLoggingReceiveThread>(logmsg_cb);
    m_log_rcv_threadcaller->SetNetworkMode(Config::IsNetworkEnabled());

    // start monitoring and logging publishing thread
    CMonLogPublishingThread::MonitoringCallbackT mon_cb = std::bind(&CMonitoringImpl::GetMonitoringMsg, this, std::placeholders::_1);
    CMonLogPublishingThread::LoggingCallbackT    log_cb = std::bind(&CMonitoringImpl::GetLoggingMsg, this, std::placeholders::_1);
    m_pub_threadcaller = std::make_shared<CMonLogPublishingThread>(mon_cb, log_cb);

    // setup blacklist and whitelist filter strings#
    m_topic_filter_excl_s = Config::GetMonitoringFilterExcludeList();
    m_topic_filter_incl_s = Config::GetMonitoringFilterIncludeList();

    // setup filtering on by default
    SetFilterState(true);

    m_init = true;
  }

  void CMonitoringImpl::Destroy()
  {
    m_init = false;
  }

  void CMonitoringImpl::SetExclFilter(const std::string& filter_)
  {
    m_topic_filter_excl_s = filter_;
  }

  void CMonitoringImpl::SetInclFilter(const std::string& filter_)
  {
    m_topic_filter_incl_s = filter_;
  }

  void CMonitoringImpl::SetFilterState(bool state_)
  {
    if (state_)
    {
      // create excluding filter list
      {
        std::lock_guard<std::mutex> lock(m_topic_filter_excl_mtx);
        Tokenize(m_topic_filter_excl_s, m_topic_filter_excl, ",;", true);
      }

      // create including filter list
      {
        std::lock_guard<std::mutex> lock(m_topic_filter_incl_mtx);
        Tokenize(m_topic_filter_incl_s, m_topic_filter_incl, ",;", true);
      }
    }
    else
    {
      {
        std::lock_guard<std::mutex> lock(m_topic_filter_excl_mtx);
        m_topic_filter_excl.clear();
      }
      {
        std::lock_guard<std::mutex> lock(m_topic_filter_incl_mtx);
        m_topic_filter_incl.clear();
      }
    }
  }

  size_t CMonitoringImpl::ApplySample(const eCAL::pb::Sample& ecal_sample_, eCAL::pb::eTLayerType /*layer_*/)
  {
    // if sample is from outside and we are in local network mode
    // do not process sample
    if (!IsLocalHost(ecal_sample_) && !m_network) return 0;

    switch (ecal_sample_.cmd_type())
    {
    case eCAL::pb::bct_none:
    case eCAL::pb::bct_set_sample:
      break;
    case eCAL::pb::bct_reg_process:
    {
      // register process
      RegisterProcess(ecal_sample_);
    }
    break;
    case eCAL::pb::bct_reg_service:
    {
      // register service
      RegisterServer(ecal_sample_);
    }
    break;
    case eCAL::pb::bct_reg_client:
    {
      // register client
      RegisterClient(ecal_sample_);
    }
    break;
    case eCAL::pb::bct_reg_publisher:
    {
      // register publisher
      RegisterTopic(ecal_sample_, CMonitoringImpl::publisher);
    }
    break;
    case eCAL::pb::bct_reg_subscriber:
    {
      // register subscriber
      RegisterTopic(ecal_sample_, CMonitoringImpl::subscriber);
    }
    break;
    default:
    {
      eCAL::Logging::Log(log_level_debug1, "CMonitoringImpl::ApplySample : unknown sample type");  
    }
    break;
    }
    return 0;
  }

  bool CMonitoringImpl::RegisterTopic(const eCAL::pb::Sample& sample_, enum ePubSub pubsub_type_)
  {
    auto& sample_topic = sample_.topic();

    // check blacklist topic filter
    {
      std::lock_guard<std::mutex> lock(m_topic_filter_excl_mtx);
      for (const auto& it : m_topic_filter_excl)
      {
        if (std::regex_match(sample_topic.tname(), std::regex(it, std::regex::icase)))
          return(false);
      }
    }

    // check whitelist topic filter
    bool is_topic_in_filter(false);
    {
      std::lock_guard<std::mutex> lock(m_topic_filter_incl_mtx);
      is_topic_in_filter = m_topic_filter_incl.empty();
      for (const auto& it : m_topic_filter_incl)
      {
        if (std::regex_match(sample_topic.tname(), std::regex(it, std::regex::icase)))
        {
          is_topic_in_filter = true;
          break;
        }
      }
    }

    if (is_topic_in_filter == false) return (false);

    /////////////////////////////////
    // register in topic map
    /////////////////////////////////
    STopicMonMap* pTopicMap = GetMap(pubsub_type_);
    if (pTopicMap)
    {
      // acquire access
      std::lock_guard<std::mutex> lock(pTopicMap->sync);

      // try to get topic info
      std::string topic_name_id = sample_topic.tname() + sample_topic.tid();
      STopicMon& TopicInfo = (*pTopicMap->map)[topic_name_id];
      TopicInfo.sample = sample_topic;
      //TopicInfo.sample.mutable_tlayer()->Clear();
      //for (auto& layer : sample_topic.tlayer()) {
      //  if (!layer.confirmed()) continue;
      //  *TopicInfo.sample.mutable_tlayer()->Add() = layer;
      //}

      // update flexible content
      TopicInfo.rclock++;
    }

    return(true);
  }

  bool CMonitoringImpl::RegisterProcess(const eCAL::pb::Sample& sample_)
  {
    auto sample_process = sample_.process();
    std::string     host_name                    = sample_process.hname();
    std::string     process_name                 = sample_process.pname();
    int             process_id                   = sample_process.pid();
    std::string     process_param                = sample_process.pparam();
    std::string     unit_name                    = sample_process.uname();
    long long       process_memory               = sample_process.pmemory();
    float           process_cpu                  = sample_process.pcpu();
    float           process_usrptime             = sample_process.usrptime();
    long long       process_datawrite            = sample_process.datawrite();
    long long       process_dataread             = sample_process.dataread();
    auto            sample_process_state         = sample_process.state();
    int             process_state_severity       = sample_process_state.severity();
    int             process_state_severity_level = sample_process_state.severity_level();
    std::string     process_state_info           = sample_process_state.info();
    int             process_tsync_state          = sample_process.tsync_state();
    std::string     process_tsync_mod_name       = sample_process.tsync_mod_name();
    int             component_init_state         = sample_process.component_init_state();
    std::string     component_init_info          = sample_process.component_init_info();
    std::string     ecal_runtime_version         = sample_process.ecal_runtime_version();

    std::stringstream process_id_ss;
    process_id_ss << process_id;
    std::string process_name_id = process_name + process_id_ss.str();

    // acquire access
    std::lock_guard<std::mutex> lock(m_process_map.sync);

    // try to get process info
    SProcessMon& ProcessInfo = (*m_process_map.map)[process_name_id];

    // set static content
    ProcessInfo.hname  = std::move(host_name);
    ProcessInfo.pname  = std::move(process_name);
    ProcessInfo.uname  = std::move(unit_name);
    ProcessInfo.pid    = process_id;
    ProcessInfo.pparam = std::move(process_param);

    // update flexible content
    ProcessInfo.rclock++;
    ProcessInfo.pmemory              = process_memory;
    ProcessInfo.pcpu                 = process_cpu;
    ProcessInfo.usrptime             = process_usrptime;
    ProcessInfo.datawrite            = process_datawrite;
    ProcessInfo.dataread             = process_dataread;
    ProcessInfo.state_severity       = process_state_severity;
    ProcessInfo.state_severity_level = process_state_severity_level;
    ProcessInfo.state_info           = std::move(process_state_info);
    ProcessInfo.tsync_state          = process_tsync_state;
    ProcessInfo.tsync_mod_name       = std::move(process_tsync_mod_name);
    ProcessInfo.component_init_state = component_init_state;
    ProcessInfo.component_init_info  = std::move(component_init_info);
    ProcessInfo.ecal_runtime_version = std::move(ecal_runtime_version);

    return(true);
  }

  bool CMonitoringImpl::RegisterServer(const eCAL::pb::Sample& sample_)
  {
    auto sample_service = sample_.service();
    std::string  host_name    = sample_service.hname();
    std::string  service_name = sample_service.sname();
    std::string  service_id   = sample_service.sid();
    std::string  process_name = sample_service.pname();
    std::string  unit_name    = sample_service.uname();
    int          process_id   = sample_service.pid();
    int          tcp_port     = sample_service.tcp_port();

    std::stringstream process_id_ss;
    process_id_ss << process_id;
    std::string service_name_id = service_name + service_id + process_id_ss.str();

    // acquire access
    std::lock_guard<std::mutex> lock(m_server_map.sync);

    // try to get service info
    SServerMon& ServerInfo = (*m_server_map.map)[service_name_id];

    // set static content
    ServerInfo.hname    = std::move(host_name);
    ServerInfo.sname    = std::move(service_name);
    ServerInfo.sid      = std::move(service_id);
    ServerInfo.pname    = std::move(process_name);
    ServerInfo.uname    = std::move(unit_name);
    ServerInfo.pid      = process_id;
    ServerInfo.tcp_port = tcp_port;

    // update flexible content
    ServerInfo.rclock++;
    ServerInfo.methods.clear();
    for (int i = 0; i < sample_.service().methods_size(); ++i)
    {
      struct SMethodMon method;
      auto sample_service_methods = sample_.service().methods(i);
      method.mname      = sample_service_methods.mname();
      method.req_type   = sample_service_methods.req_type();
      method.req_desc   = sample_service_methods.req_desc();
      method.resp_type  = sample_service_methods.resp_type();
      method.resp_desc  = sample_service_methods.resp_desc();
      method.call_count = sample_service_methods.call_count();
      ServerInfo.methods.push_back(method);
    }

    return(true);
  }

  bool CMonitoringImpl::RegisterClient(const eCAL::pb::Sample& sample_)
  {
    auto sample_client = sample_.client();
    std::string  host_name    = sample_client.hname();
    std::string  service_name = sample_client.sname();
    std::string  service_id   = sample_client.sid();
    std::string  process_name = sample_client.pname();
    std::string  unit_name    = sample_client.uname();
    int          process_id   = sample_client.pid();

    std::stringstream process_id_ss;
    process_id_ss << process_id;
    std::string service_name_id = service_name + service_id + process_id_ss.str();

    // acquire access
    std::lock_guard<std::mutex> lock(m_client_map.sync);

    // try to get service info
    SClientMon& ClientInfo = (*m_client_map.map)[service_name_id];

    // set static content
    ClientInfo.hname = std::move(host_name);
    ClientInfo.sname = std::move(service_name);
    ClientInfo.sid   = std::move(service_id);
    ClientInfo.pname = std::move(process_name);
    ClientInfo.uname = std::move(unit_name);
    ClientInfo.pid = process_id;

    // update flexible content
    ClientInfo.rclock++;

    return(true);
  }

  void CMonitoringImpl::RegisterLogMessage(const eCAL::pb::LogMessage& log_msg_)
  {
    std::lock_guard<std::mutex> lock(m_log_msglist_sync);
    m_log_msglist.emplace_back(log_msg_);
  }

  CMonitoringImpl::STopicMonMap* CMonitoringImpl::GetMap(enum ePubSub pubsub_type_)
  {
    STopicMonMap* pHostMap = nullptr;
    switch (pubsub_type_)
    {
    case publisher:
      pHostMap = &m_publisher_map;
      break;
    case subscriber:
      pHostMap = &m_subscriber_map;
      break;
    }
    return(pHostMap);
  };

  void CMonitoringImpl::GetMonitoringMsg(eCAL::pb::Monitoring& monitoring_)
  {
    // clear protobuf object
    monitoring_.Clear();

    // write all registrations to monitoring message object
    MonitorProcs(monitoring_);
    MonitorServer(monitoring_);
    MonitorClients(monitoring_);
    MonitorTopics(m_publisher_map, monitoring_, "publisher");
    MonitorTopics(m_subscriber_map, monitoring_, "subscriber");
  }

  void CMonitoringImpl::GetLoggingMsg(eCAL::pb::Logging& logging_)
  {
    // clear protobuf object
    logging_.Clear();

    // acquire access
    std::lock_guard<std::mutex> lock(m_log_msglist_sync);

    LogMessageListT::const_iterator siter = m_log_msglist.begin();
    while (siter != m_log_msglist.end())
    {
      // add log message
      eCAL::pb::LogMessage* pMonLogMessage = logging_.add_logs();

      // copy content
      pMonLogMessage->CopyFrom(*siter);

      ++siter;
    }

    // empty message list
    m_log_msglist.clear();
  }

  int CMonitoringImpl::PubMonitoring(bool state_, std::string & name_)
  {
    // (de)activate monitor publisher
    m_pub_threadcaller->SetMonState(state_, name_);
    return 0;
  }

  int CMonitoringImpl::PubLogging(bool state_, std::string & name_)
  {
    // (de)activate logging publisher
    m_pub_threadcaller->SetLogState(state_, name_);
    return 0;
  }

  void CMonitoringImpl::MonitorProcs(eCAL::pb::Monitoring& monitoring_)
  {
    // acquire access
    std::lock_guard<std::mutex> lock(m_process_map.sync);

    // iterate map
    m_process_map.map->remove_deprecated();
    for (auto process : (*m_process_map.map))
    {
      // add host
      eCAL::pb::Process* pMonProcs = monitoring_.add_processes();

      // registration clock
      pMonProcs->set_rclock(process.second.rclock);

      // host name
      pMonProcs->set_hname(process.second.hname);

      // process name
      pMonProcs->set_pname(process.second.pname);

      // unit name
      pMonProcs->set_uname(process.second.uname);

      // process id
      pMonProcs->set_pid(process.second.pid);

      // process parameter
      pMonProcs->set_pparam(process.second.pparam);

      // process memory
      pMonProcs->set_pmemory(process.second.pmemory);

      // process cpu
      pMonProcs->set_pcpu(process.second.pcpu);

      // process user core time
      pMonProcs->set_usrptime(process.second.usrptime);

      // process data write bytes
      pMonProcs->set_datawrite(process.second.datawrite);

      // process data read bytes
      pMonProcs->set_dataread(process.second.dataread);

      // state
      auto state = pMonProcs->mutable_state();

      // severity state
      state->set_severity(eCAL::pb::eProcessSeverity(process.second.state_severity));

      // severity level
      state->set_severity_level(eCAL::pb::eProcessSeverityLevel(process.second.state_severity_level));

      // severity info
      state->set_info(process.second.state_info);

      // time synchronization state
      pMonProcs->set_tsync_state(eCAL::pb::eTSyncState(process.second.tsync_state));

      // time synchronization module name
      pMonProcs->set_tsync_mod_name(process.second.tsync_mod_name);

      // eCAL component initialization state
      pMonProcs->set_component_init_state(process.second.component_init_state);

      // eCAL component initialization info
      pMonProcs->set_component_init_info(process.second.component_init_info);

      // eCAL component runtime version
      pMonProcs->set_ecal_runtime_version(process.second.ecal_runtime_version);
    }
  }

  void CMonitoringImpl::MonitorServer(eCAL::pb::Monitoring& monitoring_)
  {
    // acquire access
    std::lock_guard<std::mutex> lock(m_server_map.sync);

    // iterate map
    m_server_map.map->remove_deprecated();
    for (auto service : (*m_server_map.map))
    {
      // add host
      eCAL::pb::Service* pMonService = monitoring_.add_services();

      // registration clock
      pMonService->set_rclock(service.second.rclock);

      // host name
      pMonService->set_hname(service.second.hname);

      // process name
      pMonService->set_pname(service.second.pname);

      // unit name
      pMonService->set_uname(service.second.uname);

      // process id
      pMonService->set_pid(service.second.pid);

      // service name
      pMonService->set_sname(service.second.sname);

      // service id
      pMonService->set_sid(service.second.sid);

      // tcp port
      pMonService->set_tcp_port(service.second.tcp_port);

      // methods
      for (auto method : service.second.methods)
      {
        eCAL::pb::Method* pMonMethod = pMonService->add_methods();
        pMonMethod->set_mname(method.mname);
        pMonMethod->set_req_type(method.req_type);
        pMonMethod->set_req_desc(method.req_desc);
        pMonMethod->set_resp_type(method.resp_type);
        pMonMethod->set_resp_desc(method.resp_desc);
        pMonMethod->set_call_count(method.call_count);
      }
    }
  }

  void CMonitoringImpl::MonitorClients(eCAL::pb::Monitoring& monitoring_)
  {
    // acquire access
    std::lock_guard<std::mutex> lock(m_client_map.sync);

    // iterate map
    m_client_map.map->remove_deprecated();
    for (auto service : (*m_client_map.map))
    {
      // add host
      eCAL::pb::Client* pMonClient = monitoring_.add_clients();

      // registration clock
      pMonClient->set_rclock(service.second.rclock);

      // host name
      pMonClient->set_hname(service.second.hname);

      // process name
      pMonClient->set_pname(service.second.pname);

      // unit name
      pMonClient->set_uname(service.second.uname);

      // process id
      pMonClient->set_pid(service.second.pid);

      // service name
      pMonClient->set_sname(service.second.sname);

      // service id
      pMonClient->set_sid(service.second.sid);
    }
  }

  void CMonitoringImpl::MonitorTopics(STopicMonMap& map_, eCAL::pb::Monitoring& monitoring_, const std::string& direction_)
  {
    // acquire access
    std::lock_guard<std::mutex> lock(map_.sync);

    // iterate map
    map_.map->remove_deprecated();
    for (auto topic : (*map_.map))
    {
      // add topic
      eCAL::pb::Topic* pMonTopic = monitoring_.add_topics();
      *pMonTopic = topic.second.sample;

      // registration clock
      pMonTopic->set_rclock(topic.second.rclock);

      // direction
      pMonTopic->set_direction(direction_);
    }
  }

  void CMonitoringImpl::Tokenize(const std::string& str, StrICaseSetT& tokens, const std::string& delimiters, bool trimEmpty)
  {
    std::string::size_type pos, lastPos = 0;

    for (;;)
    {
      pos = str.find_first_of(delimiters, lastPos);
      if (pos == std::string::npos)
      {
        pos = str.length();
        if (pos != lastPos || !trimEmpty)
        {
          tokens.emplace(std::string(str.data() + lastPos, pos - lastPos));
        }
        break;
      }
      else
      {
        if (pos != lastPos || !trimEmpty)
        {
          tokens.emplace(std::string(str.data() + lastPos, pos - lastPos));
        }
      }
      lastPos = pos + 1;
    }
  }
}
