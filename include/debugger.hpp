#ifndef MINIDBG_DEBUGGER_HPP
#define MINIDBG_DEBUGGER_HPP

#include <utility>
#include <string>
#include <linux/types.h>
#include <unordered_map>
#include <fcntl.h>


#include "breakpoint.hpp"
#include "dwarf/dwarf++.hh"
#include "elf/elf++.hh"

namespace minidbg{
    class debugger
    {
        public:
               debugger(std::string prog_name, pid_t pid)
                   : m_prog_name{std::move(prog_name)},m_pid{pid}
                   {
                       //ELF加载器需要一个Unix文件描述符(可以映射到内存而不是每次读一点它)，所以用open而不是ifstream
                        auto fd = open(m_prog_name.c_str(),O_RDONLY);
                        m_elf = elf::elf(elf::create_mmap_loader(fd));
                        m_dwarf = dwarf::dwarf(dwarf::elf::create_loader(m_elf));
                   }
               
            void run();

            void set_breakpoint_at_address(std::intptr_t addr);
            void dump_registers();

            // 打印源码上下文
            void print_source(const std::string& file_name, unsigned line, unsigned n_line_context=2);
            
            
        private:
            void handle_command(const std::string& line);
            void continue_execution();
            auto get_pc()-> uint64_t;
            void set_pc(uint64_t pc);
            void step_over_breakpoint();
            void wait_for_signal();
            // ptrace获取信号信息，如产生原因
            auto get_signal_info() -> siginfo_t;
            // 特别处理sigtrap信号
            void handle_sigtrap(siginfo_t info);

            auto read_memory(uint64_t address) ->uint64_t;
            void write_memory(uint64_t address, uint64_t value);

            //加载受控程序基地址
            void initialise_load_address();
            //获取地址偏移
            u_int64_t offset_load_address(u_int64_t addr);

            // dwarf::die debugger::get_function_from_pc(uint64_t pc)
            auto get_function_from_pc(uint64_t pc) ->dwarf::die;
            // dwarf::line_table::iterator debugger::get_line_entry_from_pc(uint64_t pc);
            auto get_line_entry_from_pc(uint64_t pc) ->dwarf::line_table::iterator;
            // dwarf::line_table::iterator get_line_entry_from_pc(uint64_t pc);

            std::string m_prog_name;
            pid_t m_pid;
            uint64_t m_load_address = 0;
            std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;//hashmap保存地址->断点的映射，以便快速查找此处是否有断点

            dwarf::dwarf m_dwarf;
            elf::elf m_elf;
    };


}


#endif
