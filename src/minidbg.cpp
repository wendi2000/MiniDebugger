/* ************************************************************************
> File Name:     main.cpp
> Author:        Wendy
> Created Time:  2022年02月04日 星期五 10时48分14秒
> Description:   
 ************************************************************************/

#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <fstream>

#include <sys/types.h>
#include <sys/stat.h>

#include "linenoise.h"

#include "debugger.hpp"
#include "registers.hpp"
#include <sys/personality.h>

using namespace minidbg;

// ptrace获取信号信息，如产生原因，返回存储相关信息的结构体
siginfo_t debugger::get_signal_info()
{
    siginfo_t info;
    ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);
    return info;
}


// 打印源码上下文
void debugger::print_source
(const std::string& file_name, 
unsigned line, unsigned n_line_context)
{
    std::ifstream file(file_name);

    // 为了美化输出，画一些分割线
    auto start_line = line <= n_line_context ? 1:line-n_line_context;
    auto end_line = line + n_line_context 
                    + (line < n_line_context ? n_line_context : 0) + 1;

    char c{};
    auto current_line = 1u;
    // 跳过start_line前面的行，更新当前行
    while(current_line != start_line && file.get(c))
    {
        if(c=='\n') ++current_line;
    }

    // 如果我们在当前行，则输出光标
    std::cout << (current_line==line ? ">" : " ");

    // 输出每一行，直到end_line
    while(current_line <= end_line && file.get(c))
    {
        std::cout << c;
        if(c == '\n')
        {
            ++current_line;
            // 如果我们在当前行，则输出光标
            std::cout << (current_line==line ? ">" : " ");
        }
    }
    // 输出流刷新
    std::cout << std::endl;
}
    



//获取地址偏移
 u_int64_t debugger::offset_load_address(u_int64_t addr)
{
    return addr - m_load_address;
}


//根据PC在debug_line表检索相关条目
dwarf::line_table::iterator debugger::get_line_entry_from_pc(uint64_t pc)
{
    for(auto& cu: m_dwarf.compilation_units())//遍历所有编译单元
    {
        if(die_pc_range(cu.root()).contains(pc))
        {
            auto &lt = cu.get_line_table();//获取编译单元的.debug_line
            auto it = lt.find_address(pc);//
            if(it == lt.end())
            {
                throw std::out_of_range{"cannot find line entry"};
            }
            else
            {
                return it;
            }
        }
    }
    throw std::out_of_range{"cannot find line entry"};
}

//根据PC检索dwarf信息条目得到函数die
dwarf::die debugger::get_function_from_pc(uint64_t pc)
{
    // 普通函数
    for(auto &cu : m_dwarf.compilation_units())//遍历所有编译单元
    {
        if(die_pc_range(cu.root()).contains(pc))
        {
            for(const auto& die : cu.root())
            {
                if(die.tag == dwarf::DW_TAG::subprogram)////遍历所有die中的函数
                {
                    if(die_pc_range(die).contains(pc))
                    {
                        return die;
                    }
                }
            }
        }
    }
    throw std::out_of_range{"Cannot find function"};
    // 内联函数

    // 成员函数
}

// 特别处理sigtrap信号
void debugger::handle_sigtrap(siginfo_t info)
{
    switch (info.si_code)
    {
    case SI_KERNEL:
    case TRAP_BRKPT:
    {
        set_pc(get_pc()-1);//put the pc back where it should be
        std::cout << "Hit breakpoint at address 0x"
                << std::hex << get_pc() << std::endl;
        // 获取当前地址偏移，以查询dwarf
        auto offset_pc = offset_load_address(get_pc());
        // 根据偏移pc得到.debug_line信息
        auto line_entry = get_line_entry_from_pc(offset_pc);
        // 打印源码上下文
        print_source(line_entry->file->path, line_entry->line);
        return;
    }
    // 如果信号是通过单步发送的，这将被设置
    case TRAP_TRACE:
        return;
    default:
        std::cout << "Unknown SIGTRAP code " << info.si_code << std::endl;
        // break;
        return;
    }
}

void debugger::wait_for_signal()
{
    int wait_status;
    auto options=0;
    waitpid(m_pid, &wait_status, options);

    // 获取所收信号的信息结构体
    auto siginfo = get_signal_info();

    switch(siginfo.si_signo)
    {
        case SIGTRAP:
            handle_sigtrap(siginfo);
            break;
        case SIGSEGV:
            std::cout << "Yay, segfault. Reason: "
                    << siginfo.si_code << std::endl;
            break;
        default:
            std::cout << "Got signal " 
                    << strsignal(siginfo.si_signo) << std::endl;
    }
}

//步过：遇到函数不会进入函数单步执行，而是将函数执行完再停止
void debugger::step_over_breakpoint()
{
    
    // auto possible_breakpoint_location = get_pc() -1;//pc是下一条指令，-1得到当前指令

    if(m_breakpoints.count(get_pc()))//在断点hashmap查找当前位置是否有下断点
    {
        auto& bp = m_breakpoints[get_pc()];//获取该断点对象

        if(bp.is_enabled())
        {
            // auto previous_instruction_address = possible_breakpoint_location;
            // set_pc(previous_instruction_address);//让pc指向当前已经执行过的指令

            bp.disable();//禁用该断点，这样程序才能执行过去
            ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);//让OS重启子进程，当子进程执行了下一条指令再停止，并通知父进程
            wait_for_signal();
            bp.enable();//重新启用断点（恢复设置）
            
        }

    }
}


//获取、设置(受控进程的)程序计数器(pc/rip存储CPU即将要执行的指令地址)（完善continue功能）
uint64_t debugger::get_pc()
{
    return get_register_value(m_pid, reg::rip);
}

void debugger::set_pc(uint64_t pc)
{
    set_register_value(m_pid, reg::rip, pc);
}

//内存的读写可以直接使用ptrace
uint64_t debugger::read_memory(uint64_t address)
{
    return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

void debugger::write_memory(uint64_t address, uint64_t value)
{
    ptrace(PTRACE_POKEDATA, m_pid, address, value);
}

//输出所有的寄存器
void debugger::dump_registers()
{
	for(const auto& rd: g_register_descriptors)//全局变量
	{
		  std::cout << rd.name << " 0x"
			    << std::setfill('0') << std::setw(16)
			    << std::hex << get_register_value(m_pid, rd.r) << std::endl;//全局函数
	}
}

//根据delimiter分割s，返回string的vector
std::vector<std::string> split(const std::string &s, char delimiter)
{
    std::vector<std::string> out{};
    std::stringstream ss{s};
    std::string item;

    while(std::getline(ss, item, delimiter))
    {
        out.push_back(item);
    }
    return out;

}

//判断s是否属于of的前缀
bool is_prefix(const std::string& s, const std::string& of)
{
    if(s.size() > of.size()) return false;
    return std::equal(s.begin(), s.end(), of.begin());
}


void debugger::handle_command(const std::string& line)
{
    auto args = split(line,' ');
    auto command = args[0];

    if(is_prefix(command, "continue"))
    {
        continue_execution();
    }
    else if(is_prefix(command, "break"))
    {
        std::string addr{args[1],2};//从args[1]的第2索引开始取值（相当于删除字符串前两个字符0x）
        set_breakpoint_at_address(std::stol(addr,0,16));//地址格式由字符串转16进制数
    }
    else if(is_prefix(command, "register"))
    {
        if(is_prefix(args[1], "dump"))
        {
            dump_registers();
        }
        else if(is_prefix(args[1], "read")) //register read rax
        {
            std::cout << get_register_value(m_pid, get_register_from_name(args[2])) << std::endl;
        }
        else if(is_prefix(args[1], "write")) //register write rax 0x42
        {
            std::string val{
                args[3],2
            };
            set_register_value(m_pid, get_register_from_name(args[2]), std::stol(val, 0, 16));
        }
    }
    else if(is_prefix(command, "memory"))
    {
        std::string addr{
            args[2],2
        };
        if(is_prefix(args[1], "read"))//memory read 0xdeadbeef
        {
            std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << std::endl;
        }
        if(is_prefix(args[1], "write"))//memory write 0xdeadbeef 0xcafe
        {
            std::string val{
                args[3],2
            };
            write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
        }
    }
    else
    {
        std::cerr << "Unknown command\n";
    }
}

void debugger::set_breakpoint_at_address(std::intptr_t addr)
    {
        std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl;
        breakpoint bp(m_pid, addr);
        bp.enable();
        m_breakpoints[addr] = bp;
    }

//加载受控程序基地址
void debugger::initialise_load_address()
{
    // 如果程序是动态链接的
    if(m_elf.get_hdr().type == elf::et::dyn)
    {
        // 可以在/proc/pid/maps中找到加载地址
        std::ifstream map("/proc" + std::to_string(m_pid) + "/maps");

        // 开始读取
        std::string addr;
        std::getline(map, addr, '-');
        //多行取map文件输入流，直到遇到分隔符
        // 相当于读取第一个地址

        m_load_address = std::stoi(addr, 0, 16);
    }
}


void debugger::run()
{
    // int wait_status;
    // auto options=0;
    // waitpid(m_pid, &wait_status, options);//暂停当前进程，直到有信号来，返回值放在wait_status
    wait_for_signal();

    // 对于可能开启了PIE的程序，需要先查找程序的加载基地址
    // 再将PC偏移加上基地址，得到真实地址
    initialise_load_address();

    char* line = 0;
    while((line = linenoise("Wendydbg> ")) != 0)//监听并得到用户输入
    {
        handle_command(line);//处理命令
        linenoiseHistoryAdd(line);//命令存入历史
        linenoiseFree(line);//释放资源
    }
}


void debugger::continue_execution()
{
    step_over_breakpoint();
    ptrace(PTRACE_CONT, m_pid, 0, 0);//告诉被控进程继续运行
    
    //int wait_status;
    //auto options=0;
    //waitpid(m_pid, &wait_status, options);//阻塞，直到收到信号
    wait_for_signal();
}





int main(int argc, char* argv[])
{
    if(argc < 2)
    {
        std::cerr << "Program name not specified";
        return -1;
    }

    auto prog = argv[1];

    auto pid = fork();
    if(pid == 0)
    {
        //we are in the child process
        //execute debugee
        
        //禁用地址空间布局随机化ASLR
        personality(ADDR_NO_RANDOMIZE);

        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);//系统调用：让父进程跟踪子进程，父进程通过读取寄存器、读取内存、单步执行等方式来观察和控制子进程的执行。arg1表示我们想做什么（PTACRE_TRACEME指定父进程来跟踪它），arg2表示被跟踪的进程ID
        execl(prog, prog, nullptr);

    }else if(pid >=1) //pid of child process
    {
        //we are in the parent process
        //execute debugger
        std::cout << "Started debugging process " << pid << '\n';
        debugger dbg(prog, pid);
        dbg.run();
    }
}


