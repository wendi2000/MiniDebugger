#ifndef MINIDBG_DEBUGGER_HPP
#define MINIDBG_DEBUGGER_HPP

#include <utility>
#include <string>
#include <linux/types.h>
#include<unordered_map>


#include "breakpoint.hpp"

namespace minidbg{
    class debugger
    {
        public:
               debugger(std::string prog_name, pid_t pid)
                   : m_prog_name{
                       std::move(prog_name)
                   },m_pid{
                       pid
                   }{

                   }
            void run();

            void set_breakpoint_at_address(std::intptr_t addr);
        private:
            void handle_command(const std::string& line);
            void continue_execution();

            std::string m_prog_name;
            pid_t m_pid;
            std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;//hashmap保存地址->断点的映射，以便快速查找此处是否有断点
    };

    

}


#endif
