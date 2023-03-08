#pragma once

#include <string>
#include <vector>
#include <map>

#include <ecal/ecal_tlayer.h>

namespace eCAL
{
    class CPublisherConfig
    {
    public:
        CPublisherConfig();
        virtual ~CPublisherConfig();
        bool ParseFile(const std::string& config_json_path);
        const std::vector<TLayer::eTransportLayer> *CustomTransportPriorityByTopicName(const std::string &);
        const std::vector<TLayer::eTransportLayer> *CustomTransportPriorityByTopicType(const std::string &);

    private:
        std::map<std::string, std::vector<TLayer::eTransportLayer>> custom_trans_by_topic_names_, custom_trans_by_topic_types_;
    };
}