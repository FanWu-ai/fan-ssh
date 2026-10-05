/* Ordinary-user tracing of our own static Go test child only.
   Bind newly created IPv4 UDP sockets to an explicitly supplied physical NIC.
   No system routes, firewall, executable or unrelated process is modified. */
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <net/if.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
struct state {pid_t tid; int udp,inject; struct user_regs_struct original; unsigned long address, words[4];};
static struct state slots[256];static const char *device;static int bound;
static void fail(const char *s){perror(s);exit(78);}
static struct state *slot(pid_t tid){for(int i=0;i<256;i++)if(slots[i].tid==tid)return &slots[i];for(int i=0;i<256;i++)if(!slots[i].tid){slots[i].tid=tid;return &slots[i];}fail("thread limit");return NULL;}
static unsigned long peek(pid_t tid,unsigned long at){errno=0;unsigned long value=ptrace(PTRACE_PEEKDATA,tid,at,0);if(value==(unsigned long)-1 && errno)fail("read own child");return value;}
int main(int argc,char **argv){
 if(argc<2 || geteuid()==0 || geteuid()!=getuid())return 78;device=getenv("FANSSH_NATIVE_DEVICE");if(!device || !*device || strlen(device)>=IFNAMSIZ || !if_nametoindex(device))return 78;
 pid_t child=fork();if(child<0)fail("fork");if(!child){if(ptrace(PTRACE_TRACEME,0,0,0)<0)_exit(78);raise(SIGSTOP);execvp(argv[1],argv+1);_exit(78);}
 int status;if(waitpid(child,&status,0)!=child || !WIFSTOPPED(status))fail("initial stop");
 if(ptrace(PTRACE_SETOPTIONS,child,0,PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACECLONE|PTRACE_O_TRACEEXEC|PTRACE_O_EXITKILL)<0)fail("options");
 if(ptrace(PTRACE_SYSCALL,child,0,0)<0)fail("initial resume");
 for(;;){
  pid_t tid=waitpid(-1,&status,__WALL);if(tid<0){if(errno==EINTR)continue;fail("wait");}struct state *s=slot(tid);
  if(WIFEXITED(status)||WIFSIGNALED(status)){memset(s,0,sizeof(*s));if(tid==child){fprintf(stderr,"PHYSICAL_UDP_SOCKETS_BOUND=%d\n",bound);return WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status);}continue;}
  if(!WIFSTOPPED(status))continue;int sig=WSTOPSIG(status),deliver=0;
  if(sig==(SIGTRAP|0x80)){
   unsigned char info[128]={0};if(ptrace(PTRACE_GET_SYSCALL_INFO,tid,sizeof(info),info)<0)fail("syscall info");
   struct user_regs_struct r;if(ptrace(PTRACE_GETREGS,tid,0,&r)<0)fail("registers");
   if(info[0]==1){
    if(!s->inject)s->udp=(r.orig_rax==SYS_socket && r.rdi==AF_INET && (r.rsi&15)==SOCK_DGRAM);
   }else if(info[0]==2){
    if(s->inject){
     long result=(long)r.rax;for(int i=0;i<4;i++)if(ptrace(PTRACE_POKEDATA,tid,s->address+i*sizeof(long),s->words[i])<0)fail("restore own stack");
     if(result!=0){errno=(int)-result;fail("physical device bind");}
     if(ptrace(PTRACE_SETREGS,tid,0,&s->original)<0)fail("restore own registers");s->inject=0;bound++;fprintf(stderr,"PHYSICAL_UDP_BOUND\n");
    }else if(s->udp && (long)r.rax>=0){
     s->udp=0;s->original=r;s->address=r.rsp-128;
     unsigned long instruction=peek(tid,r.rip-2);if((instruction&65535)!=0x050f){errno=EINVAL;fail("syscall instruction");}
     unsigned char bytes[32]={0};memcpy(bytes,device,strlen(device));
     for(int i=0;i<4;i++){s->words[i]=peek(tid,s->address+i*sizeof(long));unsigned long word;memcpy(&word,bytes+i*sizeof(long),sizeof(long));if(ptrace(PTRACE_POKEDATA,tid,s->address+i*sizeof(long),word)<0)fail("device argument");}
     r.rdi=r.rax;r.rsi=SOL_SOCKET;r.rdx=SO_BINDTODEVICE;r.r10=s->address;r.r8=strlen(device)+1;r.rax=SYS_setsockopt;r.orig_rax=SYS_setsockopt;r.rip-=2;
     s->inject=1;if(ptrace(PTRACE_SETREGS,tid,0,&r)<0)fail("inject own socket option");
    }else s->udp=0;
   }
  }else if(sig!=SIGSTOP && sig!=SIGTRAP)deliver=sig;
  if(ptrace(PTRACE_SYSCALL,tid,0,deliver)<0 && errno!=ESRCH)fail("resume child");
 }
}
