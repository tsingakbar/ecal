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
 * @file   client.h
 * @brief  eCAL Client interface based on protobuf service description
**/

#pragma once

#include <ecal/ecal_client.h>
#include <ecal/protobuf/ecal_proto_hlp.h>

// protobuf includes
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4100 4127 4146 4505 4800 4189 4592) // disable proto warnings
#endif
#include <google/protobuf/descriptor.pb.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

// stl includes
#include <string>

namespace eCAL
{
  namespace protobuf
  {
    /**
     * @brief Google Protobuf Client wrapper class.
    **/
    template <typename T>
    class CServiceClient : public eCAL::CServiceClient
    {
    public:
      /**
       * @brief Constructor (using protobuf defined service name).
       *
      **/
      CServiceClient()
      {
        Create(T::descriptor()->full_name());
      }

      /**
       * @brief Constructor.
       *
       * @param service_name_  Unique service name.
      **/
      CServiceClient(const std::string& service_name_)
      {
        Create(service_name_);
      }

      /**
       * @brief CServiceClients are non-copyable
      **/
      CServiceClient(const CServiceClient&) = delete;

      /**
       * @brief CServiceClients are non-copyable
      **/
      CServiceClient& operator=(const CServiceClient&) = delete;

      /**
       * @brief Call a method of this service, responses will be returned by callback. 
       *
       * @param method_name_  Method name.
       * @param request_      Request message.
       * @param timeout_      Maximum time before operation returns (in milliseconds, -1 means infinite).
       *
       * @return  True if successful.
      **/
      bool Call(const std::string& method_name_, const google::protobuf::Message& request_, const int timeout_ = -1)
      {
        return Call(method_name_, request_.SerializeAsString(), timeout_);
      }

      /**
       * @brief Call a method of this service, all responses will be returned in service_response_vec.
       *
       * @param       method_name_           Method name.
       * @param       request_               Request message.
       * @param       timeout_               Maximum time before operation returns (in milliseconds, -1 means infinite).
       * @param [out] service_response_vec_  Response vector containing service responses from every called service (null pointer == no response).
       *
       * @return  True if successful.
      **/
      bool Call(const std::string& method_name_, const google::protobuf::Message& request_, const int timeout_, ServiceResponseVecT* service_response_vec_)
      {
        return Call(method_name_, request_.SerializeAsString(), timeout_, service_response_vec_);
      }

      /**
       * @brief Call a method of this service asynchronously, responses will be returned by callback.
       *
       * @param method_name_  Method name.
       * @param request_      Request message.
       * @param timeout_      Maximum time before operation returns (in milliseconds, -1 means infinite).
       *
       * @return  True if successful.
      **/
      bool CallAsync(const std::string& method_name_, const google::protobuf::Message& request_, const int timeout_ = -1)
      {
        return CallAsync(method_name_, request_.SerializeAsString(), timeout_);
      }

      using eCAL::CServiceClient::Call;
      using eCAL::CServiceClient::CallAsync;
    };
  }
}
