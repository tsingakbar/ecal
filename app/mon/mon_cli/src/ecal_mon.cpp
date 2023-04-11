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
 * @brief eCALMon Console Application
**/

#include <atomic>
#include <iostream>
#include <chrono>
#include <thread>
#include <asio.hpp>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4100 4127 4146 4505 4800 4189 4592) // disable proto warnings
#endif
#include <google/protobuf/message.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include "tclap/CmdLine.h"

#include <ecal/msg/protobuf/dynamic_subscriber.h>
#include <ecal/ecal.h>
#include <ecal/msg/string/publisher.h>
#include <ecal/msg/string/subscriber.h>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4100 4127 4146 4505 4800 4189 4592) // disable proto warnings
#endif
#include <ecal/core/pb/monitoring.pb.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include "ecal_mon_defs.h"

#define GetMessageA GetMessage

enum class CmdOption
{
  version,
  bandwidth,
  echo,
  proto,
  find,
  rate,
  info,
  list,
  pub,
  type,
  desc,
  tcpdump_filter,
};

const int _1kB = 1024;
const int _10kB = 10 * _1kB;
const int _1MB = _1kB * _1kB;
const int _10MB = 10 * _1MB;
int pause_val = 500;

void ProcBandwidth(const std::string& topic_name);
void ProcEcho(const std::string& topic_name,  int msg_count);
void ProcProto(const std::string& topic_name, int msg_count);
void ProcFind(const std::string& topic_type);
void ProcRate(const std::string& topic_name);
void ProcInfo(const std::string& topic_name);
void ProcList();
void ProcPub(const std::string& topic_name, const std::string& data);
void ProcType(const std::string& topic_name);
void ProcDesc(const std::string& topic_name);
void ProcTcpdumpFilter(const std::string& topic_name);

// main entry
int main(int argc, char** argv)
{
  try
  {
    // initialize protobuf
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    /************************************************************************/
    /* Create & Parse the command line                                      */
    /************************************************************************/
    // Define the command line object.
    std::string version_str = std::string(ECAL_MON_VERSION) + " (" + std::string(ECAL_MON_DATE) + ")";
    TCLAP::CmdLine cmd(ECAL_MON_NAME, ' ' , version_str);

    std::vector<std::reference_wrapper<TCLAP::Arg>> args;
    // Define the values from argument and add them to the command line.
    TCLAP::SwitchArg list_arg("l", "list", "print information about active topics", false);
    args.push_back(list_arg);
    TCLAP::ValueArg<std::string> info_arg("i", "info", "print information about active topics", false, "", "string");
    args.push_back(info_arg);
    TCLAP::ValueArg<std::string> find_arg("f", "find", "find topics by type", false, "", "string");
    args.push_back(find_arg);
    TCLAP::ValueArg<std::string> type_arg("t", "type", "print topic type", false, "", "string");
    args.push_back(type_arg);
    TCLAP::ValueArg<std::string> desc_arg("d", "desc", "print topic description", false, "", "string");
    args.push_back(desc_arg);
    TCLAP::ValueArg<std::string> tcpdump_arg("", "tcpdump", "print topic transport layer tcpdump filter", false, "", "string");
    args.push_back(tcpdump_arg);

    TCLAP::ValueArg<std::string> rate_arg("r", "rate", "display publishing rate of topic", false, "", "string");
    args.push_back(rate_arg);
    TCLAP::ValueArg<std::string> bandwidth_arg("b", "bandwidth", "display bandwidth used by topic", false, "", "string");
    args.push_back(bandwidth_arg);

    TCLAP::ValueArg<std::string> echo_arg("e", "echo", "print string messages to screen", false, "", "string");
    args.push_back(echo_arg);
    TCLAP::ValueArg<std::string> proto_arg("", "proto", "print protobuf messages to screen", false, "", "string");
    args.push_back(proto_arg);
    TCLAP::ValueArg<int> count_arg("c", "count", "exit application after a defined number of received messages (used with --echo or --proto option)", false, 0, "int");
    args.push_back(count_arg);

    TCLAP::ValueArg<std::string> pub_arg("p", "pub", "publish string data to topic", false, "", "string");
    args.push_back(pub_arg);
    TCLAP::ValueArg<std::string> message_arg("m", "msg", "message to publish", false, "", "string");
    args.push_back(message_arg);

    TCLAP::ValueArg<int> pause_arg("", "pause", "sleep between command execution [ms]", false, 0, "int");
    args.push_back(pause_arg);

    // usage display order is reversed with adding order
    for (auto itr = args.rbegin(); itr != args.rend(); ++itr) cmd.add(itr->get());

    // Parse the argv array.
    cmd.parse(argc, argv);

    /************************************************************************/
    /*                                                                      */
    /************************************************************************/
    CmdOption cmd_option(CmdOption::version);

    std::string topic_name;
    std::string topic_type;
    std::string message;
    int         message_count(-1);

    if (bandwidth_arg.getValue().empty() == false)
    {
      topic_name = bandwidth_arg.getValue();
      cmd_option = CmdOption::bandwidth;
    }
    if (echo_arg.getValue().empty() == false)
    {
      topic_name = echo_arg.getValue();
      cmd_option = CmdOption::echo;
    }
    if (proto_arg.getValue().empty() == false)
    {
      topic_name = proto_arg.getValue();
      cmd_option = CmdOption::proto;
    }
    if (find_arg.getValue().empty() == false)
    {
      topic_type = find_arg.getValue();
      cmd_option = CmdOption::find;
    }
    if (rate_arg.getValue().empty() == false)
    {
      topic_name = rate_arg.getValue();
      cmd_option = CmdOption::rate;
    }
    if (info_arg.getValue().empty() == false)
    {
      topic_name = info_arg.getValue();
      cmd_option = CmdOption::info;
    }
    if (list_arg.getValue() == true)
    {
      cmd_option = CmdOption::list;
    }
    if (pub_arg.getValue().empty() == false)
    {
      topic_name = pub_arg.getValue();
      cmd_option = CmdOption::pub;
    }
    if (message_arg.getValue().empty() == false)
    {
      message = message_arg.getValue();
    }
    if (type_arg.getValue().empty() == false)
    {
      topic_name = type_arg.getValue();
      cmd_option = CmdOption::type;
    }
    if (desc_arg.getValue().empty() == false)
    {
      topic_name = desc_arg.getValue();
      cmd_option = CmdOption::desc;
    }
    if (tcpdump_arg.getValue().empty() == false)
    {
      topic_name = tcpdump_arg.getValue();
      cmd_option = CmdOption::tcpdump_filter;
    }
    if (count_arg.isSet())
    {
      message_count = count_arg.getValue();
      if (message_count < 0) message_count = 0;
    }
    if (pause_arg.getValue() > 0)
    {
      pause_val = pause_arg.getValue();
    }

    // initialize eCAL API
    eCAL::Initialize(0, nullptr, "eCALTopic", eCAL::Init::All);

    // set process state
    eCAL::Process::SetState(proc_sev_healthy, proc_sev_level1, "Running");

    switch (cmd_option)
    {
    case CmdOption::bandwidth:
      ProcBandwidth(topic_name);
      break;
    case CmdOption::echo:
      ProcEcho(topic_name, message_count);
      break;
    case CmdOption::proto:
      ProcProto(topic_name, message_count);
      break;
    case CmdOption::find:
      ProcFind(topic_type);
      break;
    case CmdOption::rate:
      ProcRate(topic_name);
      break;
    case CmdOption::info:
      ProcInfo(topic_name);
      break;
    case CmdOption::list:
      ProcList();
      break;
    case CmdOption::pub:
      ProcPub(topic_name, message);
      break;
    case CmdOption::type:
      ProcType(topic_name);
      break;
    case CmdOption::desc:
      ProcDesc(topic_name);
      break;
    case CmdOption::tcpdump_filter:
      ProcTcpdumpFilter(topic_name);
      break;
    default:
      break;
    }

    // shutdown protobuf
    google::protobuf::ShutdownProtobufLibrary();

    // finalize eCAL API
    eCAL::Finalize();
  }
  catch (TCLAP::ArgException &e)  // catch any exceptions
  {
    std::cerr << "error: " << e.error() << " for arg " << e.argId() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

//////////////////////////////////////////
// display bandwidth used by topic
//////////////////////////////////////////
void ProcBandwidth(const std::string& topic_name)
{
  std::cout << "display bandwidth for topic " << topic_name << std::endl << std::endl;

  // monitoring instance to store complete snapshot
  eCAL::pb::Monitoring monitoring;

  // sleep 1 s
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));

  while(eCAL::Ok())
  {
    // take snapshot :-)
    static std::string monitoring_s;
    if(eCAL::Monitoring::GetMonitoring(monitoring_s))
    {
      monitoring.ParseFromString(monitoring_s);
    }

    // for all topics
    bool found = false;
    for(const auto& topic : monitoring.topics())
    {
      // check topic name
      if(topic.tname() != topic_name) continue;
      found = true;

      std::string unit = "Byte/s";
      auto bw = topic.tsize() * (topic.dfreq()/1000.0);
      if (bw > _10MB)
      {
        bw /= _1MB;
        unit = "MByte/s";
      }
      else
      {
        if(bw > _10kB)
        {
          bw /= _1kB;
          unit = "kByte/s";
        }
      }
      std::cout << int(bw) << " " << unit << " (" << topic.hname() << ":"  << topic.direction() << ")" << std::endl;
    }

    if(!found) std::cout << "." << std::endl;
    else       std::cout        << std::endl;

    // sleep
    std::this_thread::sleep_for(std::chrono::milliseconds(pause_val));
  }
}

//////////////////////////////////////////
// print string messages to screen
//////////////////////////////////////////
void ProcEcho(const std::string& topic_name, int msg_count)
{
  std::cout << "echo string message output for topic " << topic_name << std::endl << std::endl;;

  // create string subscriber for topic topic_name_ and assign callback
  eCAL::string::CSubscriber<std::string> sub(topic_name);
  std::atomic<int> cnt(msg_count);
  auto msg_cb = [&cnt](const std::string& msg_) { if (cnt != 0) { std::cout << msg_ << std::endl; if (cnt > 0) cnt--; } };
  sub.AddReceiveCallback(std::bind(msg_cb, std::placeholders::_2));

  while(eCAL::Ok() && (cnt != 0))
  {
    // sleep 500 ms
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
}

//////////////////////////////////////////
// print protobuf messages to screen
//////////////////////////////////////////
void ProcProto(const std::string& topic_name, int msg_count)
{
  std::cout << "echo protobuf message output for topic " << topic_name << std::endl << std::endl;;

  // sleep 1000 ms
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));

  // get topic type
  std::string topic_type = eCAL::Util::GetTopicTypeName(topic_name);
  if(topic_type.empty())
  {
    std::cout << "could not get type for topic " << topic_name << std::endl;
    return;
  }

  // create dynamic subscribers for receiving and decoding messages and assign callback
  eCAL::protobuf::CDynamicSubscriber sub(topic_name);
  std::atomic<int> cnt(msg_count);
  auto msg_cb = [&cnt](const google::protobuf::Message &msg_)
  { if (cnt != 0) { std::cout << msg_.DebugString() << std::endl; if (cnt > 0) cnt--; } };
  sub.AddReceiveCallback(std::bind(msg_cb, std::placeholders::_2));

  // enter main loop
  while(eCAL::Ok() && (cnt != 0))
  {
    // sleep 500 ms
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
}

//////////////////////////////////////////
// find topics by type
//////////////////////////////////////////
void ProcFind(const std::string& topic_type)
{
  std::cout << "display all topics with type " << topic_type << std::endl << std::endl;;

  // monitoring instance to store complete snapshot
  eCAL::pb::Monitoring monitoring;

  // sleep 1 s
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));

  while(eCAL::Ok())
  {
    // take snapshot :-)
    static std::string monitoring_s;
    if(eCAL::Monitoring::GetMonitoring(monitoring_s))
    {
      monitoring.ParseFromString(monitoring_s);
    }

    // for all topics
    for(const auto& topic : monitoring.topics())
    {
      // check topic name
      if(topic.ttype() != topic_type) continue;

      // print topic details
      std::cout << "tname        : " << topic.tname()     << std::endl;   // topic name
      std::cout << "ttype        : " << topic.ttype()     << std::endl;   // topic type
      std::cout << "direction    : " << topic.direction() << std::endl;   // direction (publisher, subscriber)
      std::cout << "hname        : " << topic.hname()     << std::endl;   // host name
      std::cout << "pid          : " << topic.pid()       << std::endl;   // process id
      std::cout << "tid          : " << topic.tid()       << std::endl;   // topic id
      std::cout << std::endl;
    }

    // sleep
    std::this_thread::sleep_for(std::chrono::milliseconds(pause_val));
  }
}

//////////////////////////////////////////
// display publishing rate of topic
//////////////////////////////////////////
void ProcRate(const std::string& topic_name)
{
  std::cout << "display data rate [Hz] for topic " << topic_name << std::endl << std::endl;;

  // monitoring instance to store complete snapshot
  eCAL::pb::Monitoring monitoring;

  // sleep 1 s
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));

  while(eCAL::Ok())
  {
    // take snapshot :-)
    static std::string monitoring_s;
    if(eCAL::Monitoring::GetMonitoring(monitoring_s))
    {
      monitoring.ParseFromString(monitoring_s);
    }

    // for all topics
    for(const auto& topic : monitoring.topics())
    {
      // check topic name
      if(topic.tname() != topic_name) continue;
      std::cout << topic.dfreq()/1000.0 << std::endl; // data frequency (send / receive samples per second * 1000)
    }

    // sleep
    std::this_thread::sleep_for(std::chrono::milliseconds(pause_val));
  }
}

//////////////////////////////////////////
// print information about active topic
//////////////////////////////////////////
void ProcInfo(const std::string& topic_name)
{
  std::cout << "display topic details for " << topic_name << std::endl << std::endl;;

  // monitoring instance to store complete snapshot
  eCAL::pb::Monitoring monitoring;

  // sleep 1 s
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));

  while(eCAL::Ok())
  {
    // take snapshot :-)
    static std::string monitoring_s;
    if(eCAL::Monitoring::GetMonitoring(monitoring_s))
    {
      monitoring.ParseFromString(monitoring_s);
    }

    // for all topics
    for(const auto& topic : monitoring.topics())
    {
      // check topic name
      if(topic.tname() != topic_name) continue;

      std::cout << topic.Utf8DebugString() << std::endl;
    }

    // sleep
    std::this_thread::sleep_for(std::chrono::milliseconds(pause_val));
  }
}

//////////////////////////////////////////
// print information about active topics
//////////////////////////////////////////
void ProcList()
{
  std::cout << "display topic details for all active topics" << std::endl << std::endl;;

  // monitoring instance to store complete snapshot
  eCAL::pb::Monitoring monitoring;

  // sleep 1 s
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));

  while(eCAL::Ok())
  {
    // take snapshot :-)
    static std::string monitoring_s;
    if(eCAL::Monitoring::GetMonitoring(monitoring_s))
    {
      monitoring.ParseFromString(monitoring_s);
    }

    // for all topics
    for(const auto& topic : monitoring.topics())
    {
      // print topic details
      std::cout << "tname        : " << topic.tname()        << std::endl;   // topic name
      std::cout << "ttype        : " << topic.ttype()        << std::endl;   // topic type
      std::cout << "direction    : " << topic.direction()    << std::endl;   // direction (publisher, subscriber)
      std::cout << "hname        : " << topic.hname()        << std::endl;   // host name
      std::cout << "pid          : " << topic.pid()          << std::endl;   // process id
      std::cout << "tid          : " << topic.tid()          << std::endl;   // topic id
      std::cout << "tsize        : " << topic.tsize()        << std::endl;   // topic size
      std::cout << "dclock       : " << topic.dclock()       << std::endl;   // data clock (send / receive action)
      std::cout << "dfreq        : " << topic.dfreq()/1000.0 << std::endl;   // data frequency (send / receive samples per second * 1000)
      std::cout << std::endl;
    }

    // sleep
    std::this_thread::sleep_for(std::chrono::milliseconds(pause_val));
  }
}

//////////////////////////////////////////
// publish string data to topic
//////////////////////////////////////////
void ProcPub(const std::string& topic_name, const std::string& data)
{
  std::cout << "publish " << data << " on topic " << topic_name << std::endl << std::endl;;

  // create string publisher for topic topic_name_
  eCAL::string::CPublisher<std::string> pub(topic_name);

  // sleep 1 s
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));

  std::string msg = data;
  while(eCAL::Ok())
  {
    // publish content
    std::cout << "publishing   " << msg << "   on topic   " << topic_name << std::endl;
    pub.Send(msg); 

    // sleep
    std::this_thread::sleep_for(std::chrono::milliseconds(pause_val));
  }
}

//////////////////////////////////////////
// print topic type
//////////////////////////////////////////
void ProcType(const std::string& topic_name)
{
  std::cout << "print type of topic " << topic_name << std::endl << std::endl;;

  // monitoring instance to store complete snapshot
  eCAL::pb::Monitoring monitoring;

  // sleep 1 s
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));

  // take snapshot :-)
  static std::string monitoring_s;
  if(eCAL::Monitoring::GetMonitoring(monitoring_s))
  {
    monitoring.ParseFromString(monitoring_s);
  }

  // for all topics
  for(const auto& topic : monitoring.topics())
  {
    // check topic name
    if(topic.tname() != topic_name) continue;

    std::string ttype = topic.ttype();
    if(ttype.empty()) ttype = "unknown";

    // print topic type
    std::cout << ttype << " (" << topic.hname() << ":"  << topic.direction() << ")" << std::endl;
  }
}

//////////////////////////////////////////
// print topic description
//////////////////////////////////////////
void ProcDesc(const std::string& topic_name_)
{
  std::cout << "print description of topic " << topic_name_ << std::endl << std::endl;;

  // monitoring instance to store complete snapshot
  eCAL::pb::Monitoring monitoring;

  // sleep 1 s
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));

  // take snapshot :-)
  static std::string monitoring_s;
  if(eCAL::Monitoring::GetMonitoring(monitoring_s))
  {
    monitoring.ParseFromString(monitoring_s);
  }

  // for all topics
  for(const auto& topic : monitoring.topics())
  {
    // check topic name
    if((topic.tname() != topic_name_) || topic.ttype().empty()) continue;

    // print topic description
    std::cout << topic.tdesc() << " (" << topic.hname() << ":"  << topic.direction() << ")" << std::endl;
  }
}

void ProcTcpdumpFilter(const std::string& topic_name_)
{
  std::cout << "print tcpdump filter for topic " << topic_name_ << std::endl << std::endl;;

  // monitoring instance to store complete snapshot
  eCAL::pb::Monitoring monitoring;

  // sleep 1 s
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));

  // take snapshot :-)
  static std::string monitoring_s;
  if(eCAL::Monitoring::GetMonitoring(monitoring_s))
  {
    monitoring.ParseFromString(monitoring_s);
  }

  class HostnameResolver
  {
  public:
    std::string Resolve(const std::string &hostname)
    {
      auto itr_cache_hit = hostname_resolve_cache_.find(hostname);
      if (itr_cache_hit != hostname_resolve_cache_.end())
        return itr_cache_hit->second;

      asio::io_context io_ctxt;
      asio::ip::tcp::resolver resolver(io_ctxt);
      asio::ip::tcp::resolver::query query(hostname, "");
      asio::error_code ec;
      auto resolve_results = resolver.resolve(query, ec);
      for (auto &resolve : resolve_results)
      {
        if (!resolve.endpoint().address().is_v4())
          continue;
        auto resolved = resolve.endpoint().address().to_string();
        hostname_resolve_cache_.insert({hostname, resolved});
        return resolved;
      }
      return hostname;
    }

  private:
    std::map<std::string, std::string> hostname_resolve_cache_;
  } resolver;

  // for all topics
  for(const auto& topic : monitoring.topics())
  {
    // check topic name
    if((topic.tname() != topic_name_) || topic.ttype().empty()) continue;
    if (topic.direction() != "publisher") continue;

    for (auto &trans_layer : topic.tlayer())
    {
      switch (trans_layer.type())
      {
      case eCAL::pb::tl_ecal_udp_mc:
      {
        const auto &mc_dst_addr = trans_layer.par_layer().layer_par_udpmc().mc_dst_addr();
        const auto mc_dst_port = trans_layer.par_layer().layer_par_udpmc().mc_dst_port();
        if (!mc_dst_addr.empty() && mc_dst_port > 0)
          // do not use port in case tcpdump is unable to recognize ip segmented udp packets.
          // NOTE: multiple topic might share same mc_dst_addr
          std::cout << "dst net " << mc_dst_addr << std::endl;
        break;
      }
      case eCAL::pb::tl_ecal_tcp:
      {
        auto publisher_hostname = resolver.Resolve(topic.hname());
        const auto publisher_listen_port = trans_layer.par_layer().layer_par_tcp().port();
        if (publisher_listen_port > 0) {
          std::cout << "host " << publisher_hostname << " and tcp port " << publisher_listen_port << std::endl;
        }
        break;
      }
      default:
        break;
      }
    }
  }
}
