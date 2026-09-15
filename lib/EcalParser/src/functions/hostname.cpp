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

#include "hostname.h"

#include <unistd.h>

namespace EcalParser
{
  std::string FunctionHostname::Evaluate(const std::string& /*parameters*/, std::chrono::system_clock::time_point /*time*/) const
  {
    static std::string hostname;
    
    if (hostname.empty())
    {

      char hostname_char[1024] = { 0 };
      if (gethostname(hostname_char, 1024) == 0)
      {
        hostname = hostname_char;
      }
    }
    
    return hostname;
  }

  std::string FunctionHostname::ParameterUsage   () const { return ""; }

  std::string FunctionHostname::ParameterExample() const { return ""; }
  std::string FunctionHostname::Description     () const { return "Hostname"; }
  std::string FunctionHostname::HtmlDocumentation        () const { return "<p>Evaluates to the hostname of this machine / the target machine.</p>"; }
}