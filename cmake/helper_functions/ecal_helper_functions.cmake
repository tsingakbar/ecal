# ========================= eCAL LICENSE =================================
#
# Copyright (C) 2016 - 2019 Continental Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#      http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# ========================= eCAL LICENSE =================================

# This function will set the output names of the target according to eCAL conventions.
function(ecal_get_platform_toolset)
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(eCAL_VS_TOOLSET "x64" PARENT_SCOPE)
  else()
    set(eCAL_VS_TOOLSET "Win32" PARENT_SCOPE)
  endif()
endfunction()


# This function will mark the executable as a Windows GUI application on a Windows System
function(ecal_set_subsystem_windows TARGET_NAME)
endfunction()

# This function will mark the executable as a Windows console application on a Windows System
function(ecal_set_subsystem_console TARGET_NAME)
endfunction()
