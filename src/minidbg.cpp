/* ************************************************************************
> File Name:     main.cpp
> Author:        Wendy
> Created Time:  2022年02月04日 星期五 10时48分14秒
> Description:   
 ************************************************************************/

#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <unistd.h>
#include <sstream>
#include <fstream>
#include <iostream>
#include <iomanip>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#include "linenoise.h"

#include "debugger.hpp"
#include "registers.hpp"

using namespace minidbg;

// 在从libelfin获得的符号类型和我们的枚举之间进行映射
symbol_type to_symbol_type(elf::stt sym)
{
    switch (sym)
    {
        case elf::stt::notype: return symbol_type::notype;
        case elf::stt::object: return symbol_type::object;
        case elf::stt::func: return symbol_type::func;
        case elf::stt::section: return symbol_type::section;
        case elf::stt::file: return symbol_type::file;
        default: return symbol_type::notype;
    }
};

// 查找符号
std::vector<symbol> debugger::lookup_symbol(const std::string& name)
{
    std::vector<symbol> syms;

    for(auto &sec : m_elf.sections())
    {
        if(sec.get_hdr().type != elf::sht::symtab
        && sec.get_hdr().type != elf::sht::dynsym)
            continue;
        
        for(auto sym : sec.as_symtab())
        {
            if(sym.get_name() == name)
            {
                auto &d = sym.get_data();
                syms.push_back(symbol{
                    to_symbol_type(d.type()),
                    sym.get_name(),
                    d.value
                    });
            } 
        }
    }
    return syms;
}

// 判断s是不是of的后缀
bool is_suffix(const std::string& s, const std::string& of)
{

    // s="aab" of ="ccffeaab" diff = 5   aab==aab
    if(s.size() > of.size()) return false;
    auto diff = of.size() - s.size();
    return std::equal(s.begin(), s.end(), of.begin() + diff);

}

// 在源码行上设置断点
void debugger::set_breakpoint_at_source_line(const std::string& file, unsigned line)
{
    // 在多个文件（多个编译单元）中，根据后缀匹配选出自己想要下断点的文件
    for(const auto& cu : m_dwarf.compilation_units())
    {
        if(is_suffix(file, at_name(cu.root())))
        {
            const auto& lt = cu.get_line_table();
            // 获取行表，并编译其中条目
            for(const auto& entry : lt)
            {
                // entry.is_stmt 检查行表条目是否被标记为语句的开头，
                // 该语句由编译器设置在它认为是断点的最佳目标的地址上。
                if(entry.is_stmt && entry.line == line)
                {
                    set_breakpoint_at_address(offset_dwarf_address(entry.address));
                    return;
                }
            }
        }
    }
}


// 在函数名（源码级）上设置断点
void debugger::set_breakpoint_at_function(const std::string& name)
{
    // 与之前的算法类似
    // 遍历所有编译单元的所有函数die
    for(const auto &cu : m_dwarf.compilation_units())
    {
        for(const auto& die : cu.root())
        {
            // 
            if(die.has(dwarf::DW_AT::name) && at_name(die) == name)
            {
                // at_low_pc 和 at_high_pc 是来自 libelfin 的函数，
                // 它们将为我们提供给定函数 DIE 的低 PC 值和高 PC 值。
                auto low_pc = at_low_pc(die);
                auto entry = get_line_entry_from_pc(low_pc);
                ++entry;//跳过函数序言（prologue）．直接到用户代码起始地址
                set_breakpoint_at_address(offset_dwarf_address(entry->address));
            }
        }
    }
}

// 步过
void debugger::step_over()
{
    //根据PC地址偏移检索dwarf信息条目得到函数die
    auto func = get_function_from_pc(get_offset_pc());
    // at_low_pc 和 at_high_pc 是来自 libelfin 的函数，
    // 它们将为我们提供给定函数 DIE 的低 PC 值和高 PC 值。
    auto func_entry = at_low_pc(func);
    auto func_end = at_high_pc(func);

    // 子函数起始行
    auto line = get_line_entry_from_pc(func_entry);
    // 当前所在行
    auto start_line = get_line_entry_from_pc(get_offset_pc());

    // intptr_t 和uintptr_t 在不同平台上不一样，
    // 始终与地址位数相同，用来存放地址，以此保证平台的通用性
    std::vector<std::intptr_t> to_delete{};//我们需要删除我们设置的任何断点

    // 为了设置所有的断点，我们循环遍历行表条目，直到我们碰到一个超出函数范围的断点。
    while(line->address < func_end)
    {
        auto load_address = offset_dwarf_address(line->address);
        // 对于每一个，我们确保它不是我们当前所在的行，并且在该位置还没有设置断点
        if(line->address != start_line->address 
            && !m_breakpoints.count(load_address))
            {
                set_breakpoint_at_address(load_address);
                to_delete.push_back(load_address);
            }
        ++line;
    }

    // 获取受控进程的rbp值,进而读取栈中返回地址
    auto frame_pointer = get_register_value(m_pid, reg::rbp);
    auto return_address = read_memory(frame_pointer+8);
    // 在返回地址设置断点
    if(!m_breakpoints.count(return_address))
    {
        set_breakpoint_at_address(return_address);
        to_delete.push_back(return_address);
    }

    // 继续执行，直到其中一个断点被命中，然后删除我们设置的所有临时断点。
    continue_execution();

    for(auto addr : to_delete)
    {
        remove_breakpoint(addr);
    }

}


// 根据偏移地址，返回真实地址
u_int64_t debugger::offset_dwarf_address(u_int64_t addr)
{
    return addr + m_load_address;
}

// 获取当前pc地址偏移
u_int64_t debugger::get_offset_pc()
{
    return offset_load_address(get_pc());
}

// 步进
void debugger::step_in()
{
    // 获取当前pc偏移值，去.debug_line查找得到结构体对象指针
    // 使用→解引用访问line成员
    auto line = get_line_entry_from_pc(get_offset_pc())->line;

    // 一行源码语句可能对应多个汇编指令，我们要实现源码级别步进
    // 因此要把一行源码语句包含的所有汇编指令都单步执行完
    while(get_line_entry_from_pc(get_offset_pc())->line == line)
    {
        single_step_instruction_with_breakpoint_check();
    }
    // 此时到达了新的一行源码语句
    // 获取该行调试信息，并打印输出，完成一个步进操作
    auto line_entry = get_line_entry_from_pc(get_offset_pc());
    print_source(line_entry->file->path, line_entry->line);

}
//去除一个地址的断点
void debugger::remove_breakpoint(std::intptr_t addr)
{
    // 断点对象关闭
    if(m_breakpoints.at(addr).is_enabled())
    {
        m_breakpoints.at(addr).disable();
    }
    // 断点记录map清除相应条目
    m_breakpoints.erase(addr);
}

// 跳出： 当单步执行到子函数内时，
// 用step out就可以执行完子函数余下部分，并返回到上一层函数。
void debugger::step_out()
{
    // 获取受控进程的栈底指针值
    auto frame_pointer = get_register_value(m_pid, reg::rbp);
    // 32bits程序的rbp+8就是返回地址
    auto return_address = read_memory(frame_pointer + 8);

    bool should_remove_breakpoint = false;
    if(!m_breakpoints.count(return_address))//如果返回地址处没有开启断点，就开启
    {
        set_breakpoint_at_address(return_address);
        should_remove_breakpoint = true;
    }

    // 继续执行完整个子函数，停在返回地址
    continue_execution();

    // 记得把放在返回地址的断点去除
    if(should_remove_breakpoint)
    {
        remove_breakpoint(return_address);
    }
    
}


// 可复用单步指令
void debugger::single_step_instruction()
{
    ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
    wait_for_signal();
}
// 带断点检查的单步指令
void debugger::single_step_instruction_with_breakpoint_check()
{
    // 首先检查我们是否需要开启或禁用断点
    if(m_breakpoints.count(get_pc()))
    {
        step_over_breakpoint();//有开启的断点则步过断点
    }
    else
    {
        single_step_instruction();//否则使用通用步过
    }

}

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

//根据PC地址偏移检索dwarf信息条目得到函数die
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

//步过断点：遇到函数不会进入函数单步执行，而是将函数执行完再停止
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

//打印所有的寄存器
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
        // std::string addr{args[1],2};//从args[1]的第2索引开始取值（相当于删除字符串前两个字符0x）
        // set_breakpoint_at_address(std::stol(addr,0,16));//地址格式由字符串转16进制数

        //break 0xdeadbeef　内存地址设置断点
        if(args[1][0] == '0' && args[1][1] == 'x')
        {
            std::string addr{args[1], 2};
            set_breakpoint_at_address(std::stol(addr, 0, 16));
        }
        // break <行号>:<文件名> 在源码行设置断点
        else if(args[1].find(':') != std::string::npos)//find函数在找不到指定值得情况下会返回string::npos
        {
            auto file_and_line = split(args[1], ':');
            set_breakpoint_at_source_line(file_and_line[0], std::stoi(file_and_line[1]));
        }
        // break 函数名 在函数名设置断点
        else
        {
            set_breakpoint_at_function(args[1]);
        }   
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
    else if(is_prefix(command, "stepi"))
    {
        single_step_instruction_with_breakpoint_check();
        // 步过后自动根据PC查询DWARF，输出源码上下文
        auto line_entry = get_line_entry_from_pc(get_pc());
        print_source(line_entry->file->path, line_entry->line);
    }
    else if(is_prefix(command, "step"))
    {
        step_in();
    }
    else if(is_prefix(command, "next"))
    {
        step_over();
    }
    else if(is_prefix(command, "finish"))
    {
        step_out();
    }
    // symbol 符号名
    else if(is_prefix(command, "symbol"))
    {
        //返回所有符合的符号结构体变量
        auto syms = lookup_symbol(args[1]);
        for(auto&& s : syms)
        {
            std::cout << s.name << ' ' << to_string(s.type) << " 0x" << std::hex << s.addr << std::endl;
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


