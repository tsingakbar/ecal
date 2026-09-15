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

#include "pipe_handler.h"


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

#include <locale>
#include <codecvt>

PipeHandler::PipeHandler(): pid_{0}
{}

PipeHandler::~PipeHandler()
{
  StopProcess();
}

bool PipeHandler::StartProcess(const std::string& executable_path)
{
  // If a child process already run then kill process first
  if (pid_ != 0)
  {
    StopProcess();
    pid_ = 0;
  }
  // Create pipe for sending data to the child's stdin
  if (pipe(child_stdin_pipe_fd_) < 0)
  {
    perror("Allocating pipe for child input redirect");
    return false;
  }
  
  // Create pipe for receiving data from the child's stdout
  if (pipe(child_stdout_pipe_fd_) < 0)
  {
    close(child_stdin_pipe_fd_[PIPE_READ]);
    close(child_stdin_pipe_fd_[PIPE_WRITE]);
    perror("Allocating pipe for child output redirect");
    return false;
  }

  // Fork this process so everything gets duplicated.
  int child_pid = fork();
  
  if (child_pid == 0)
  {
    // =======================================
    // ============ Child Process ============
    // =======================================

    // Redirect stdin to the pipe
    if (dup2(child_stdin_pipe_fd_[PIPE_READ], STDIN_FILENO) == -1) 
    {
      perror("Error redirecting STDIN to pipe");
      exit(errno);
    }

    // Redirect stdout to the pipe
    if (dup2(child_stdout_pipe_fd_[PIPE_WRITE], STDOUT_FILENO) == -1) {
      perror("Error redirecting STDOUT to pipe");
      exit(errno);
    }

    // All these are for use by parent only
    close(child_stdin_pipe_fd_[PIPE_READ]);
    close(child_stdin_pipe_fd_[PIPE_WRITE]);
    close(child_stdout_pipe_fd_[PIPE_READ]);
    close(child_stdout_pipe_fd_[PIPE_WRITE]);

    // Run child process image
    char* const argv[] {nullptr};

    int exec_errorcode = execve(executable_path.c_str(), argv, environ);

    // If we get here at all, an error occurred, but we are in the child process, so just exit
    perror((std::string("Unable to start \"") + executable_path.c_str() + "\"").c_str());
    exit(exec_errorcode);
  }
  else if (child_pid > 0)
  {
    // ========================================
    // ============ Parent Process ============
    // ========================================

    // Close unused file descriptors, these are for child only
    close(child_stdin_pipe_fd_[PIPE_READ]);
    close(child_stdout_pipe_fd_[PIPE_WRITE]); 

    pid_ = child_pid;
    return true;
  }

//    // Include error check here
//    if (NULL != szMessage) {
//      write(aStdinPipe[PIPE_WRITE], szMessage, strlen(szMessage));
//    }

//    // Just a char by char read here, you can change it accordingly
//    while (read(aStdoutPipe[PIPE_READ], &nChar, 1) == 1) {
//      write(STDOUT_FILENO, &nChar, 1);
//    }

//    // done with these in this example program, you would normally keep these
//    // open of course as long as you want to talk to the child
//    close(aStdinPipe[PIPE_WRITE]);
//    close(aStdoutPipe[PIPE_READ]);
  else
  {
    // Failed to create child
    close(child_stdin_pipe_fd_[PIPE_READ]);
    close(child_stdin_pipe_fd_[PIPE_WRITE]);
    close(child_stdout_pipe_fd_[PIPE_READ]);
    close(child_stdout_pipe_fd_[PIPE_WRITE]);
    
    return false;
  }
}

bool PipeHandler::StartProcess(const std::wstring& executable_path)
{
  //setup converter
  using convert_type = std::codecvt_utf8<wchar_t>; // Linux uses UTF8 ecoding
  std::wstring_convert<convert_type, wchar_t> converter;
  
  //use converter (.to_bytes: wstr->str, .from_bytes: str->wstr)
  std::string s_executable_path = converter.to_bytes(executable_path);
  
  return StartProcess(s_executable_path);
}

bool PipeHandler::WriteLine(const std::string& message)
{
  if (-1 == write(child_stdin_pipe_fd_[PIPE_WRITE], message.c_str(), message.size()))
  {
    perror("Error writing to pipe");
    return false;
  }
  if (-1 == write(child_stdin_pipe_fd_[PIPE_WRITE], "\n", 1))
  {
    perror("Error writing to pipe");
    return false;
  }
  
  return true;
}

std::string PipeHandler::NativeReadSome()
{
  std::string buffer(1024, ' ');
  
  ssize_t bytes_read = read(child_stdout_pipe_fd_[PIPE_READ], const_cast<char*>(buffer.data()), buffer.size());
  
  if (bytes_read < 0)
  {
    perror("Error readin from pipe");
    return "";
  }
  
  buffer.resize(bytes_read);
  
  return buffer;
}

bool PipeHandler::IsProcessAlive() const
{
  if(pid_ != 0)
  {
    int status;
    if( waitpid(pid_, &status, WNOHANG) != 0 ) {
      pid_ = 0;
    }
  }

  return (pid_ != 0);
}

bool PipeHandler::StopProcess()
{
  if(pid_ !=  0)
  {
    auto result = kill(pid_, SIGKILL);
    pid_ = 0;
    return !result;
  }

  return false;
}

std::string PipeHandler::ReadLine()
{
  std::string response_message;

  size_t line_break_pos = input_residue_.find('\n');
  if (line_break_pos != std::string::npos)
  {
    // If we still got one line in the buffer, we return it
    response_message = input_residue_.substr(0, line_break_pos);
    if (response_message.size() > 1 && (response_message.back() == '\r'))
    {
      // Remove the \r that may still be left, especially on Windows
      response_message.pop_back();
    }

    if ((line_break_pos + 1) < input_residue_.size())
    {
      input_residue_ = input_residue_.substr(line_break_pos + 1, std::string::npos);
    }
    else
    {
      input_residue_.clear();
    }
  }
  else
  {
    // If we didn't find an entire line in the buffer, we read more data until we get a line break.

    std::swap(response_message, input_residue_); // Start with the input residue as initial repsonse message value

    for (;;)
    {
      std::string buffer = NativeReadSome();

      // Check if the buffer contains a line break
      line_break_pos = buffer.find('\n');
      if (line_break_pos != std::string::npos)
      {
        // A line break was found! Lets use that.
        response_message += buffer.substr(0, line_break_pos);

        if ((line_break_pos + 1) < buffer.size())
        {
          input_residue_ = buffer.substr(line_break_pos + 1, std::string::npos);
        }
        if (response_message.size() > 1 && (response_message.back() == '\r'))
        {
          response_message.pop_back();
        }

        break;
      }
      else
      {
        // No line break. We continue looking for one.
        response_message += buffer;
      }
    }
  }

  return response_message;
}

