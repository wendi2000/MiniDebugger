#ifndef MINIDBG_BREAKPOINT_HPP
#define MINIDBG_BREAKPOINT_HPP

#include<utility>
#include<string>
#include<linux/types.h>
#include<sys/ptrace.h>
#include<cstdint>

namespace minidbg{
// 断点类
class breakpoint{
    public:
	breakpoint() = default;
        breakpoint(pid_t pid, std::intptr_t addr)    
            : m_pid(pid), m_addr(addr), m_enabled(false), m_saved_data{}{}

        void enable();
        void disable();

        auto is_enabled() const -> bool{ //lambda函数采用尾置返回类型，如果只要一个return语句，编译器可以直接推断无需指定
            return m_enabled;
        }
        auto get_address() const -> std::intptr_t{
            return m_addr;
        }

    private:
        pid_t m_pid;
        std::intptr_t m_addr;//断点地址
        bool m_enabled;
        uint8_t m_saved_data;//断点处原存放的数据/指令（以便之后恢复）
};

//开启断点
void breakpoint::enable()
{
    auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);//PTRACE_PEEKDATA读取子进程内存/寄存器中的值,返回当前的64位的地址
    m_saved_data = static_cast<uint8_t>(data & 0xff);//保存低两位bit（1字节），static_cast完成隐式执行的任何类型转换，避免编译器警告
    //2字节     uint16_t
    //4字节     uint32_t
    uint64_t int3  = 0xcc;//8字节  
    uint64_t data_with_int3 = ((data & ~0xff) | int3); //数据低位变成0xcc
    ptrace(PTRACE_POKEDATA, m_pid, m_addr, data_with_int3);//PTRACE_POKEDATA把值写入到被跟踪进程的内存/寄存器中

    m_enabled = true;    

}

//取消断点
void breakpoint::disable()
{
    //由于ptrace请求对整个字进行操作（而不是一个字节），所以需要先读取字，再恢复低字节，并写回内存
    auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
    auto restored_data = ((data & ~0xff) | m_saved_data);//低两位恢复
    ptrace(PTRACE_POKEDATA, m_pid, m_addr, restored_data);

    m_enabled = false;

}


}


#endif
