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

#include "linenoise.h"
#include "debugger.hpp"

using namespace minidbg;

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

void debugger::run()
{
    int wait_status;
    auto options=0;
    waitpid(m_pid, &wait_status, options);//暂停当前进程，直到有信号来，返回值放在wait_status

    char* line = 0;
    while((line = linenoise("Wendydbg> ")) != 0)//监听并得到用户输入
    {
        handle_command(line);//处理命令
        linenoiseHistoryAdd(line);//命令存入历史
        linenoiseFree(line);//释放资源
    }
}

void debugger::handle_command(const std::string& line)
{
    auto args = split(line,' ');
    auto command = args[0];

    if(is_prefix(command, "continue"))
    {
        continue_execution();
    }
    else
    {
        std::cerr << "Unknown command\n";
    }
}

void debugger::continue_execution()
{
    ptrace(PTRACE_CONT, m_pid, 0, 0);//告诉被控进程继续运行

    int wait_status;
    auto options=0;
    waitpid(m_pid, &wait_status, options);//阻塞，直到收到信号
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


