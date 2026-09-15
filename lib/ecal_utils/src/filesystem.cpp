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

#include <ecal_utils/filesystem.h>

  #include <cstring>    // strerror()
  #include <dirent.h>
  #include <fcntl.h>    // O_RDONLY
    #include <fts.h>      // File-tree traversal
  #include <unistd.h>

    #include <sys/sendfile.h>

#include <sys/stat.h> // stat
#include <errno.h>    // errno, ENOENT, EEXIST

#include <list>
#include <regex>
#include <iostream>

#include <ecal_utils/ecal_utils.h>

namespace EcalUtils
{
  namespace Filesystem
  {
    ////////////////////////////////////////
    // FileStatus Class
    ////////////////////////////////////////

    FileStatus::FileStatus(const std::string& path, OsStyle input_path_style)
    {
      const int error_code = stat(ToNativeSeperators(path, input_path_style).c_str(), &file_status_);
      is_ok_ = (error_code == 0);
    }

    FileStatus::~FileStatus() {}

    bool FileStatus::IsOk() const
    {
      return is_ok_;
    }

    Type FileStatus::GetType() const
    {
      if (!is_ok_)
        return Type::Unknown;

      switch (file_status_.st_mode & S_IFMT) {
      case S_IFREG:  return Type::RegularFile;
      case S_IFDIR:  return Type::Dir;
      case S_IFCHR:  return Type::CharacterDevice;
      case S_IFBLK:  return Type::BlockDevice;
      case S_IFIFO:  return Type::Fifo;
      case S_IFLNK:  return Type::SymbolicLink;
      case S_IFSOCK: return Type::Socket;
      default:       return Type::Unknown;
      }

    }

    int64_t FileStatus::FileSize() const
    {
      if (!is_ok_)
        return 0;

      return file_status_.st_size;
    }

bool FileStatus::PermissionRootRead()     const { return 0 != (file_status_.st_mode & S_IRUSR); }
    bool FileStatus::PermissionRootWrite()    const { return 0 != (file_status_.st_mode & S_IWUSR); }
    bool FileStatus::PermissionRootExecute()  const { return 0 != (file_status_.st_mode & S_IXUSR); }
    bool FileStatus::PermissionGroupRead()    const { return 0 != (file_status_.st_mode & S_IRGRP); }
    bool FileStatus::PermissionGroupWrite()   const { return 0 != (file_status_.st_mode & S_IWGRP); }
    bool FileStatus::PermissionGroupExecute() const { return 0 != (file_status_.st_mode & S_IXGRP); }
    bool FileStatus::PermissionOwnerRead()    const { return 0 != (file_status_.st_mode & S_IROTH); }
    bool FileStatus::PermissionOwnerWrite()   const { return 0 != (file_status_.st_mode & S_IWOTH); }
    bool FileStatus::PermissionOwnerExecute() const { return 0 != (file_status_.st_mode & S_IXOTH); }

    bool FileStatus::CanOpenDir() const
    {
      if (!is_ok_)
        return false;

      if (GetType() != Type::Dir)
        return false;

      bool can_open_dir(false);
      DIR *dp = opendir(path_.c_str());
      if (dp != NULL)
      {
        can_open_dir = true;
        closedir(dp);
      }

      return can_open_dir;
    }

    ////////////////////////////////////////
    // Path Functions
    ////////////////////////////////////////

    Type GetType(const std::string& path, OsStyle input_path_style)
    {
      FileStatus file_status(path, input_path_style);
      return file_status.GetType();
    }

    bool IsDir(const std::string& path, OsStyle input_path_style)
    {
      return GetType(path, input_path_style) == Type::Dir;
    }

    bool IsFile(const std::string& path, OsStyle input_path_style)
    {
      return GetType(path, input_path_style) == Type::RegularFile;
    }

    std::map<std::string, FileStatus> DirContent(const std::string& path, OsStyle input_path_style)
    {
      std::string clean_path = ToNativeSeperators(CleanPath(path, input_path_style), input_path_style);

      std::map<std::string, FileStatus> content;
      DIR *dp;
      struct dirent *dirp;
      if ((dp = opendir(clean_path.c_str())) == NULL)
      {
        std::cerr << "Error opening directory: " << strerror(errno) << std::endl;
        return content;
      }

      while ((dirp = readdir(dp)) != NULL)
      {
        std::string file_name(dirp->d_name);
        if ((file_name != ".") && (file_name != ".."))
          content.emplace(file_name, FileStatus(clean_path + "/" + std::string(dirp->d_name)));
      }
      closedir(dp);

      return content;
    }

    bool MkDir(const std::string& path, OsStyle input_path_style)
    {
      std::string native_path = ChangeSeperators(path, OsStyle::Current, input_path_style);

      mode_t mode = 0755;
      int ret = mkdir(native_path.c_str(), mode);
      return ret == 0;
    }

    bool MkPath(const std::string& path, OsStyle input_path_style)
    {
      std::string native_path = ChangeSeperators(CleanPath(path, input_path_style), OsStyle::Current, input_path_style);

      if (native_path.empty())
      {
        return false;
      }
      else if (native_path.back() == NativeSeparator(OsStyle::Current))
      {
        // Remove tailing separator
        native_path.pop_back();
      }

      // Create last directory
      if (MkDir(native_path, OsStyle::Current))
      {
        return true;
      }

      // If creating last directory did not work, we may need to create the parent
      switch (errno)
      {
      case ENOENT:
        // parent didn't exist, try to create it
      {
        size_t pos = native_path.find_last_of(NativeSeparator(OsStyle::Current));
        if (pos == std::string::npos)
          return false;
        if (!MkPath(native_path.substr(0, pos), OsStyle::Current))
          return false;
      }

      // now, try to create again
      return MkDir(native_path, OsStyle::Current);

      case EEXIST:
        // done!
        return IsDir(native_path, OsStyle::Current);

      default:
        return false;
      }
    }

#ifdef CopyFile
#define CopyFile_4c768dd038fa415ca1399214711e2b9f CopyFile
#undef CopyFile
#endif // CopyFile
    bool CopyFile(const std::string& source, const std::string& destination, OsStyle input_path_style)
#ifdef CopyFile_4c768dd038fa415ca1399214711e2b9f
#define CopyFile CopyFile_4c768dd038fa415ca1399214711e2b9f
#undef CopyFile_4c768dd038fa415ca1399214711e2b9f
#endif // CopyFile_4c768dd038fa415ca1399214711e2b9f
    {
      std::string source_clean      = ToNativeSeperators(CleanPath(source,      input_path_style), input_path_style);
      std::string destination_clean = ToNativeSeperators(CleanPath(destination, input_path_style), input_path_style);

      int input_fd {-1}, output_fd {-1};
      bool copy_succeeded {false};
      if ((input_fd = open(source_clean.c_str(), O_RDONLY)) == -1)
      {
        return false;
      }
      if ((output_fd = creat(destination_clean.c_str(), 0660)) == -1)
      {
        close(input_fd);
        return false;
      }
      off_t bytesCopied = 0;
      FileStatus file_status(source_clean, OsStyle::Current);
      int result = sendfile(output_fd, input_fd, &bytesCopied, file_status.FileSize());
      copy_succeeded = (result != -1);
      close(input_fd);
      close(output_fd);
      return copy_succeeded;
    }

    bool DeleteDir(const std::string& source, OsStyle input_path_style)
    {
      std::string clean_path = ToNativeSeperators(CleanPath(source, input_path_style), input_path_style);

      
      // This code has been taken from the open-bsd rm sourcecode:
      // http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/bin/rm/rm.c?rev=1.27
      // It has then been refactored and specialized.
      // 
      // The original code is published under the 3-Clause BSD license:
      // 
      // Copyright (c) 1990, 1993, 1994
      //	The Regents of the University of California.  All rights reserved.
      //
      // Redistribution and use in source and binary forms, with or without
      // modification, are permitted provided that the following conditions
      // are met:
      // 1. Redistributions of source code must retain the above copyright
      //    notice, this list of conditions and the following disclaimer.
      // 2. Redistributions in binary form must reproduce the above copyright
      //    notice, this list of conditions and the following disclaimer in the
      //    documentation and/or other materials provided with the distribution.
      // 3. Neither the name of the University nor the names of its contributors
      //    may be used to endorse or promote products derived from this software
      //    without specific prior written permission.

      FTS *fts;
      FTSENT *p;
      int success = true;
      
      clean_path += '\0'; // Abuse internal string buffer to build a NULL-terminated C-string
      char* argv[2];
      argv[0] = &clean_path[0];
      argv[1] = nullptr;
      
      fts = fts_open(argv, FTS_PHYSICAL, nullptr);
      if (fts == nullptr)
        return false;
      
      while ((p = fts_read(fts)) != NULL)
      {
          switch (p->fts_info)
          {
          case FTS_DNR:
            success = false;
            continue;
          case FTS_ERR:
            std::cerr << p->fts_path << ": " << strerror(p->fts_errno) << std::endl;
            return false;
          case FTS_NS:
            /*
             * FTS_NS: assume that if can't stat the file, it
             * can't be unlinked.
             */
            success = false;
            continue;
          case FTS_D:
              continue;
          case FTS_DP:
              break;
          default:
            break;
          }
  
          /*
           * If we can't read or search the directory, may still be
           * able to remove it.  Don't print out the un{read,search}able
           * message unless the remove fails.
           */
          switch (p->fts_info) {
          case FTS_DP:
          case FTS_DNR:
            if (!rmdir(p->fts_accpath))
            {
              continue;
            }
            break;
  
          case FTS_F:
          case FTS_NSOK:
          default:
            if (!unlink(p->fts_accpath))
            {
                continue;
            }
          }
          std::cerr << p->fts_path << std::endl;
          success = false;
      }
      if (errno)
          std::cerr << "fts_read" << std::endl;
      fts_close(fts);
      
      return success;
    }

    std::string GetAbsoluteRoot(const std::string& path, OsStyle input_path_style)
    {
      if ((input_path_style == OsStyle::Windows) || (input_path_style == OsStyle::Combined))
      {
        std::regex win_drive_with_slash("^[a-zA-Z]\\:[/\\\\]");    // Drive with tailing separator and optional directory
        std::regex win_drive_only("^[a-zA-Z]\\: *$");              // Drive only, after wich must not come anything
        std::regex win_network_drive("^[/\\\\]{2}[^/\\\\]+");      // Network path starting with two slashes or backslashes

        if ((std::regex_search(path, win_drive_with_slash)
          || std::regex_search(path, win_drive_only)))
        {
          // Windows local drive, consisting of drive-letter and colon
          return path.substr(0, 2);
        }
        else if (std::regex_search(path, win_network_drive))
        {
          // Window network drive, consisting of \\ and hostname
          size_t sep_pos = path.find_first_of("/\\", 2);
          return path.substr(0, sep_pos); // If no seperator was found, this will return the entire string
        }
      }

      if (input_path_style == OsStyle::Unix)
      {
        std::regex unix_slash("^/");                               // Normal Unix root
        if (std::regex_search(path, unix_slash))
        {
          return path.substr(0, 1);
        }
      }
      else if (input_path_style == OsStyle::Combined)
      {
        std::regex unix_slash("^[/\\\\]");                         // Normal Unix root (with optional windows seperator indicating the root)
        if (std::regex_search(path, unix_slash))
        {
          return path.substr(0, 1);
        }
      }

      return "";
    }

    bool IsAbsolute(const std::string& path, OsStyle input_path_style)
    {
      return GetAbsoluteRoot(path, input_path_style) != "";
    }

    bool IsRelative(const std::string& path, OsStyle input_path_style)
    {
      if (path.empty())
      {
        return false;
      }
      else
      {
        return !IsAbsolute(path, input_path_style);
      }
    }

    std::vector<std::string> CleanPathComponentList(const std::string& path, OsStyle input_path_style)
    {
      if (path.empty())
      {
        return{};
      }

      std::vector<std::string> components;

      std::string unix_style_path = ToUnixSeperators(path, input_path_style);

      // Get information about the root
      std::string root = GetAbsoluteRoot(path, input_path_style);
      bool is_absolute = (root != "");

      // Remove the root from the path (we will add it later)
      unix_style_path = unix_style_path.substr(root.size());

      // Split the relative path into its components
      std::list<std::string> splitted_path;
      EcalUtils::String::Split(unix_style_path, "/", splitted_path);

      // The components-stack that will increase and shrink depending on the folders and .. elements in the splitted path
            for (auto part_it = splitted_path.begin(); part_it != splitted_path.end(); part_it++)
      {
        if ((part_it == splitted_path.begin()) && (*part_it == ".") && !is_absolute)
        {
          // Preserve a leading ".", if the path is relative. It may indicate the working director, so we should not skip it.
          components.push_back(".");
        }
        else if (part_it->empty() || *part_it == ".")
        {
          continue;
        }
        else if (*part_it == "..")
        {
          if (is_absolute)
          {
            if (!components.empty())
            {
              // Move one folder up if we are not already at the root
              components.pop_back();
            }
          }
          else
          {
            if (!components.empty() && (components.back() != ".."))
            {
              // Move one folder up by removing it. We must not remove ".." elements that we were not able to resolve previously.
              components.pop_back();
            }
            else
            {
              components.push_back("..");
            }
          }
        }
        else
        {
          components.push_back(*part_it);
        }
      }

      return components;
    }

    std::string CleanPath(const std::string& path, OsStyle input_path_style)
    {
      if (path.empty())
        return "";

      // Split the path into its cleaned components
      std::vector<std::string> cleaned_path_components = CleanPathComponentList(path, input_path_style);

      // Check whether the path ended with a slash
      bool tailing_separator = (ToUnixSeperators(path, input_path_style).back() == '/');

      // Gather information about the root (it will not be in the components list)
      std::string root = GetAbsoluteRoot(path, input_path_style);
      root = ToUnixSeperators(root, input_path_style);
      bool is_absolute = (root != "");

      std::string cleaned_path;
      cleaned_path.reserve(path.size() + root.size() + 2);

      if (is_absolute)
      {
        cleaned_path += root;
        if (cleaned_path.back() != '/')
        {
          cleaned_path += '/';
        }
      }
      else
      {
        //cleaned_path += '.';
        //if (!cleaned_path_components.empty())
        //{
        //  cleaned_path += '/';
        //}
      }

      cleaned_path += EcalUtils::String::Join("/", cleaned_path_components);

      if (tailing_separator && (cleaned_path.back() != '/'))
      {
        cleaned_path += '/';
      }

      return cleaned_path;
    }

    std::string AbsolutePath(const std::string& base_path, const std::string& relative_path, OsStyle input_path_style)
    {
      return CleanPath(CleanPath(base_path) + "/" + relative_path, input_path_style);
    }

    std::string AbsolutePath(const std::string& relative_path, OsStyle input_path_style)
    {
      if (IsAbsolute(relative_path, input_path_style))
      {
        return CleanPath(relative_path, input_path_style);
      }
      else
      {
        return CleanPath(CurrentWorkingDir() + "/" + relative_path);
      }
    }

    std::string RelativePath(const std::string& base_path, const std::string& path, OsStyle input_path_style)
    {
      auto base_list = CleanPathComponentList(base_path, input_path_style);
      auto path_list = CleanPathComponentList(path, input_path_style);

      size_t size = (path_list.size() < base_list.size()) ? path_list.size() : base_list.size();
      unsigned int same_size(0);
      for (unsigned int i = 0; i < size; ++i)
      {
        if (path_list[i] != base_list[i])
        {
          same_size = i;
          break;
        }
      }

      std::string relative_path = "";
      if (same_size > 0)
      {
        for (unsigned int i = 0; i < base_list.size() - same_size; ++i)
        {
          relative_path += "../";
        }
      }

      for (unsigned int i = same_size; i < path_list.size(); ++i)
      {
        relative_path += path_list[i];
        if (i < path_list.size() - 1)
        {
          relative_path += "/";
        }
      }

      return relative_path;
    }

    std::string CurrentWorkingDir()
    {
      char working_dir[PATH_MAX];
      return (getcwd(working_dir, PATH_MAX) ? working_dir : std::string(""));
    }

    std::string ApplicationDir()
    {
      char app_path_buffer[PATH_MAX];
      ssize_t count { readlink("/proc/self/exe", app_path_buffer, PATH_MAX) };
      if (count < 0) return {};
      auto app_path{ std::string(app_path_buffer, static_cast<std::size_t>(count)) };
      return app_path.substr(0, app_path.find_last_of(separator));
    }

    std::string ChangeSeperators(const std::string& path, OsStyle output_path_style, OsStyle input_path_style)
    {
      std::string output;
      output.reserve(path.size());

      for (size_t i = 0; i < path.size(); i++)
      {
        if ((((input_path_style == OsStyle::Windows) || (input_path_style == OsStyle::Combined)) && (path[i] == '\\'))
          || (path[i] == '/'))
        {
          output += NativeSeparator(output_path_style);
        }
        else
        {
          output += path[i];
        }
      }

      return output;
    }

    std::string ToUnixSeperators(const std::string& path, OsStyle input_path_style)
    {
      return ChangeSeperators(path, OsStyle::Unix, input_path_style);
    }

    std::string ToNativeSeperators(const std::string& path, OsStyle input_path_style)
    {
      return ChangeSeperators(path, OsStyle::Current, input_path_style);
    }

    bool IsEqual(const std::string& path1, const std::string& path2, OsStyle compare_for)
    {
      std::string clean_path1 = ToNativeSeperators(AbsolutePath(path1, compare_for), compare_for);
      std::string clean_path2 = ToNativeSeperators(AbsolutePath(path2, compare_for), compare_for);

      // Compare the root
      std::string path1_root = GetAbsoluteRoot(clean_path1, compare_for);
      std::string path2_root = GetAbsoluteRoot(clean_path2, compare_for);

      if (compare_for == OsStyle::Windows)
      {
        // Windows is case-insensitive
        // cause warning C4244 with VS2017, VS2019
        //std::transform(path1_root.begin(), path1_root.end(), path1_root.begin(), ::tolower);
        std::transform(path1_root.begin(), path1_root.end(), path1_root.begin(),
          [](char c) {return static_cast<char>(::tolower(c)); });
        // cause warning C4244 with VS2017, VS2019
        //std::transform(path2_root.begin(), path2_root.end(), path2_root.begin(), ::tolower);
        std::transform(path2_root.begin(), path2_root.end(), path2_root.begin(),
          [](char c) {return static_cast<char>(::tolower(c)); });
      }

      if (path1_root != path2_root)
      {
        return false;
      }

      // Compare the rest
      auto path1_components = CleanPathComponentList(clean_path1, compare_for);
      auto path2_components = CleanPathComponentList(clean_path2, compare_for);

      if (path1_components.size() != path2_components.size())
      {
        return false;
      }

      auto path1_component_it = path1_components.begin();
      auto path2_component_it = path2_components.begin();

      while (path1_component_it != path1_components.end())
      {
        if (compare_for == OsStyle::Windows)
        {
          // Windows is case-insensitive
          // cause warning C4244 with VS2017, VS2019
          //std::transform(path1_component_it->begin(), path1_component_it->end(), path1_component_it->begin(), ::tolower);
          std::transform(path1_component_it->begin(), path1_component_it->end(), path1_component_it->begin(),
            [](char c) {return static_cast<char>(::tolower(c)); });
          // cause warning C4244 with VS2017, VS2019
          //std::transform(path2_component_it->begin(), path2_component_it->end(), path2_component_it->begin(), ::tolower);
          std::transform(path2_component_it->begin(), path2_component_it->end(), path2_component_it->begin(),
            [](char c) {return static_cast<char>(::tolower(c)); });
        }

        if (*path1_component_it != *path2_component_it)
        {
          return false;
        }

        ++path1_component_it;
        ++path2_component_it;
      }

      return true;
    }

    std::string FileName(const std::string& path, OsStyle input_path_style)
    {
      if (path.empty())
        return "";

      if (path.back() == '/')
        return "";

      if ((input_path_style == OsStyle::Windows) || (input_path_style == OsStyle::Combined))
      {
        if (path.back() == '\\')
          return "";
      }

      auto clean_path_component_list = CleanPathComponentList(path, input_path_style);
      
      if (clean_path_component_list.empty())
        return "";
      else
        return clean_path_component_list.back();
    }

    std::string BaseName(const std::string& path, OsStyle input_path_style)
    {
      std::string file_name = FileName(path, input_path_style);
      
      if (file_name.empty()) return ""; 

      size_t pos = file_name.find('.', 0);
      if (pos != std::string::npos)
      {
        return file_name.substr(0, pos);
      }
      else
      {
        return file_name;
      }
    }
  }
}
