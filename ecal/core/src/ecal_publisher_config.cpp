#include "ecal_publisher_config.h"

#include <fstream>
#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>

namespace eCAL
{
    CPublisherConfig::CPublisherConfig() {}

    CPublisherConfig::~CPublisherConfig() {}

    bool CPublisherConfig::ParseFile(const std::string& config_json_path) {
        std::ifstream json_ifstream(config_json_path);
        if (!json_ifstream.good()) return false;
        rapidjson::IStreamWrapper json_istream_wrapper(json_ifstream);
        rapidjson::Document jconf;
        jconf.ParseStream(json_istream_wrapper);
        if (!jconf.IsObject()) return false;
        auto parse_by_topic = [&jconf](const char *key, std::map<std::string, std::vector<TLayer::eTransportLayer>>& out_map) -> bool
        {
            auto itr_conf = jconf.FindMember(key);
            if (itr_conf == jconf.MemberEnd()) return false;
            if (!itr_conf->value.IsArray()) return false;
            for (auto& j_topic_conf : itr_conf->value.GetArray()) {
                if (!j_topic_conf.IsObject()) return false;
                auto itr_topic_key = j_topic_conf.FindMember("key");
                if (itr_topic_key == j_topic_conf.MemberEnd() || !itr_topic_key->value.IsString()) return false;
                auto itr_topic_trans = j_topic_conf.FindMember("transport");
                if (itr_topic_trans == j_topic_conf.MemberEnd() || !itr_topic_trans->value.IsArray()) return false;
                std::vector<TLayer::eTransportLayer> out_topic_trans;
                for (auto& j_trans : itr_topic_trans->value.GetArray()) {
                    if (!j_trans.IsString()) return false;
                    std::string transport_name(j_trans.GetString(), j_trans.GetStringLength());
                    if (transport_name == "inproc") {
                        out_topic_trans.push_back(TLayer::tlayer_inproc);
                    } else if (transport_name == "shm") {
                        out_topic_trans.push_back(TLayer::tlayer_shm);
                    } else if (transport_name == "tcp") {
                        out_topic_trans.push_back(TLayer::tlayer_tcp);
                    } else if (transport_name == "udp_mc") {
                        out_topic_trans.push_back(TLayer::tlayer_udp_mc);
                    } else return false;
                }
                out_map[itr_topic_key->value.GetString()] = std::move(out_topic_trans);
            }
            return true;
        };
        return parse_by_topic("by-name", custom_trans_by_topic_names_) && parse_by_topic("by-type", custom_trans_by_topic_types_);
    }

    const std::vector<TLayer::eTransportLayer> *CPublisherConfig::CustomTransportPriorityByTopicName(const std::string &tname) {
        auto itr = custom_trans_by_topic_names_.find(tname);
        if (itr == custom_trans_by_topic_names_.end()) return nullptr;
        return &itr->second;
    }

    const std::vector<TLayer::eTransportLayer> *CPublisherConfig::CustomTransportPriorityByTopicType(const std::string &ttype) {
        auto itr = custom_trans_by_topic_types_.find(ttype);
        if (itr == custom_trans_by_topic_types_.end()) return nullptr;
        return &itr->second;
    }
}