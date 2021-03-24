/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2016 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



/**
 * @defgroup dca
 * @{
 **/




/**
 * @defgroup dca
 * @{
 * @defgroup src
 * @{
 **/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>           /* Definition of AT_* constants */
#include <unistd.h>
#include "safec_lib.h"



#define LEN 14
#define BUF_LEN 20     // increase the BUF_LEN, because getting the source length is high  
#define CMD_LEN 256
#define MAXLEN 512
#define PID_SIZE 10
#define PIDOF_SIZE 50
#define MEM_STRING_SIZE 20
#define PROC_PATH_SIZE 50

#include "dcautils.h"

/**
 * @addtogroup DCA_TYPES
 * @{
 */
#ifdef LIBSYSWRAPPER_BUILD
#include "secure_wrapper.h"
#endif

#define MEM_KEY_PREFIX "mem_"
#define CPU_KEY_PREFIX "cpu_"

typedef struct proc_info {
  int           utime;                    /**< User mode jiffies */
  int           stime;                    /**< Kernel mode jiffies */
  int		cutime;                   /**< User mode jiffies with childs */
  int           cstime;                   /**< Kernel mode jiffies with childs */
  unsigned int  rss;                      /**< Resident Set Size */
} procinfo;

typedef struct _procMemCpuInfo {
  pid_t *pid;
  char processName[BUF_LEN];
  char cpuUse[BUF_LEN];
  char memUse[BUF_LEN];
  int total_instance;
} procMemCpuInfo;

/* @} */ // End of group DCA_TYPES


int getProcInfo(procMemCpuInfo *pInfo);
int getMemInfo(procMemCpuInfo *pmInfo);
int getCPUInfo(procMemCpuInfo *pInfo);

/**
 * @addtogroup DCA_APIS
 * @{
 */

/**
 * @brief To get process usage.
 *
 * @param[in] processName   Process name.
 *
 * @return  Returns status of operation.
 * @retval  0 on sucess, appropiate errorcode otherwise.
 */
int getProcUsage(char *processName) {
  if (processName != NULL) {
    procMemCpuInfo pInfo = { 0 };
    char pidofCommand[PIDOF_SIZE];
#if defined (ENABLE_PS_PROCESS_SEARCH)
    char psCommand[CMD_LEN];
#endif
    FILE *cmdPid;
    char *mem_key = NULL, *cpu_key = NULL;
    int ret = 0;
    int index = 0;
    pid_t *pid = NULL;
    pid_t *temp = NULL;
    errno_t rc = -1;
    int cpu_key_length = 0, mem_key_length = 0;

    /*
    * LIMITATION
    * Following memcpy() and sprintf() api's can't modified to safec api's
    * Because, safec has the limitation of copying only 4k ( RSIZE_MAX ) to destination
    * And here, we have source size more than 4k.
    */
    memcpy(pInfo.processName, processName, strlen(processName)+1);

    sprintf(pidofCommand, "pidof %s", processName);

#ifdef LIBSYSWRAPPER_BUILD
    if (!(cmdPid = v_secure_popen("r", "pidof %s", processName)))
#else
    if (!(cmdPid = popen(pidofCommand, "r")))
#endif
    {
      LOG("Failed to execute %s", pidofCommand);
      return 0;
    }

    pid = (pid_t *) malloc (sizeof(pid_t));
    if ( NULL == pid )
    {
#ifdef LIBSYSWRAPPER_BUILD
        v_secure_pclose(cmdPid);
#else
        pclose(cmdPid);
#endif
        return 0;
    }
    *pid=0;
    while(fscanf(cmdPid,"%d",(pid+index)) == 1)
    {
        if ((*(pid+index)) <= 0)
        {
            continue;
        }
        index++;
        temp = (pid_t *) realloc (pid,((index+1)*sizeof(pid_t)) );
        if ( NULL == temp )
        {
                free(pid);
#ifdef LIBSYSWRAPPER_BUILD
                v_secure_pclose(cmdPid);
#else
                pclose(cmdPid);
#endif
           return 0;
        }
        pid=temp;
    }

    #ifdef LIBSYSWRAPPER_BUILD
		v_secure_pclose(cmdPid);
    #else
		pclose(cmdPid);
    #endif

#if defined (ENABLE_PS_PROCESS_SEARCH) 
    // Pidof command output is empty
    if ((*pid) <= 0)
    {
        // pidof was empty, see if we can grab the pid via ps
        sprintf(psCommand, "ps | grep %s | grep -v grep | awk '{ print $1 }'", processName);

#ifdef LIBSYSWRAPPER_BUILD
        if (!(cmdPid = v_secure_popen("r", "ps | grep %s | grep -v grep | awk '{ print $1 }'", processName)))
#else
        if (!(cmdPid = popen(psCommand, "r")))
#endif
        {
            return 0;
        }

        *pid=0;
        index=0;
        while(fscanf(cmdPid,"%d",(pid+index)) == 1)
        {
            if ((*(pid+index)) <= 0)
            {
                continue;
            }
            index++;
            temp = (pid_t *) realloc (pid,((index+1)*sizeof(pid_t)) );
            if ( NULL == temp )
            {
                free(pid);
#ifdef LIBSYSWRAPPER_BUILD
                v_secure_pclose(cmdPid);
#else
                pclose(cmdPid);
#endif
                return 0;
            }
            pid=temp;
        }

    #ifdef LIBSYSWRAPPER_BUILD
		v_secure_pclose(cmdPid);
    #else
		pclose(cmdPid);
    #endif

        // If pidof command output is empty
        if ((*pid) <= 0)
        {
            free(pid);
            return 0;
        }
    }
#else
    // If pidof command output is empty
    if ((*pid) <= 0)
    {
        free(pid);
        return 0;
    }
#endif

    pInfo.total_instance=index;
    pInfo.pid=pid;

    if (getProcInfo(&pInfo) == 0) {
         LOG("Failed to get procInfo for %s", processName);
         return 0;
    }

    mem_key_length = strlen(processName) + strlen(MEM_KEY_PREFIX) + 1;
    cpu_key_length = strlen(processName) + strlen(CPU_KEY_PREFIX) + 1;
    mem_key = malloc(mem_key_length);
    cpu_key = malloc(cpu_key_length);
    if (NULL != mem_key && NULL != cpu_key)
    {
       /*
       * LIMITATION
       * Following snprintf() api's can't modified to safec api's
       * Because, safec has the limitation of copying only 4k ( RSIZE_MAX ) to destination
       * Here, we have source size more than 4k.
       */
        snprintf(cpu_key,cpu_key_length,"%s%s", CPU_KEY_PREFIX,processName);

        snprintf(mem_key,mem_key_length,"%s%s", MEM_KEY_PREFIX,processName);

        addToSearchResult(mem_key, pInfo.memUse);
        addToSearchResult(cpu_key, pInfo.cpuUse);
        ret = 1;
    }
 
    free(mem_key);
    free(cpu_key);
    free(pid);

    return ret;

  } 
  return 0;
}

/**
 * @brief To get status of a process from its process ID. 
 *
 * This will return information such as process priority, virtual memory size, signals etc.
 *
 * @param[in] pid      PID value of the  process.
 * @param[in] pinfo    Process info.
 *
 * @return  Returns status of operation.
 * @retval  Return 1 on success, appropiate errorcode otherwise.
 */
int getProcPidStat(int pid, procinfo * pinfo)
{
  char szFileName [CMD_LEN],szStatStr [2048],*s, *t;
  struct stat st;
  int ppid, pgrp, session, tty, tpgid, counter, priority, starttime, signal, blocked, sigignore, sigcatch,fd, read_len;
  char exName [CMD_LEN], state;
  unsigned euid, egid;
  unsigned int flags, minflt, cminflt, majflt, cmajflt, timeout, itrealvalue, vsize, rlim, startcode, endcode, startstack, kstkesp, kstkeip, wchan; 
  errno_t rc = -1;

  if (NULL == pinfo)
  {
    LOG("Invalid input(pinfo=NULL) to get process info");
    return 0;
  }

  rc = sprintf_s(szFileName,sizeof(szFileName),"/proc/%u/stat", (unsigned) pid);
  if(rc < EOK)
  {
    ERR_CHK(rc);
    return 0;
  }

  if ((fd = open(szFileName, O_RDONLY)) == -1)
  {
    LOG("Unable to access file in get proc info");
    return 0;
  }

  if(-1 != fstat(fd, &st)) {
        euid = st.st_uid;
        egid = st.st_gid;
  }else {
        euid = egid = -1;
  }

  read_len = read(fd, szStatStr, 2047); 
  if(read_len == -1) {
        close(fd);
        return 0;
  }
  szStatStr[read_len++] = '\0';

  /** pid **/
  s = strchr (szStatStr, '(') + 1;
  t = strchr (szStatStr, ')');

  rc = strncpy_s(exName,sizeof(exName),s,t - s);
  if(rc != EOK)
  {
    ERR_CHK(rc);
    close(fd);
    return 0;
  }
  exName [t - s] = '\0';
  if(s !=  NULL && t != NULL && (t-s) > 0){
      sscanf (t + 2, "%c %d %d %d %d %d %u %u %u %u %u %d %d %d %d %d %d %u %u %d %u %u %u %u %u %u %u %u %d %d %d %d %u",
      /*       1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33*/
      &(state),
      &(ppid),
      &(pgrp),
      &(session),
      &(tty),
      &(tpgid),
      &(flags),
      &(minflt),
      &(cminflt),
      &(majflt),
      &(cmajflt),
      &(pinfo->utime),
      &(pinfo->stime),
      &(pinfo->cutime),
      &(pinfo->cstime),
      &(counter),
      &(priority),
      &(timeout),
      &(itrealvalue),
      &(starttime),
      &(vsize),
      &(pinfo->rss),
      &(rlim),
      &(startcode),
      &(endcode),
      &(startstack),
      &(kstkesp),
      &(kstkeip),
      &(signal),
      &(blocked),
      &(sigignore),
      &(sigcatch),
      &(wchan));
}
  close (fd);

  return 1;
}

/**
 * @brief To get CPU and mem info.
 *
 * @param[out] pmInfo  Memory/CPU Info.
 *
 * @return  Returns status of operation.
 * @retval  Return 1 on success.
 */
int getProcInfo(procMemCpuInfo *pmInfo)
{
  if (0 == getMemInfo(pmInfo))
      return 0;

  if (0 == getCPUInfo(pmInfo))
      return 0;

  return 1;
}


/**
 * @brief To get the reserve memory of a given process.
 *
 * @param[out] pmInfo  Memory  Info.
 *
 * @return  Returns status of operation.
 * @retval  Return 1 on success.
 */
int getMemInfo(procMemCpuInfo *pmInfo)
{
  static char retMem[MEM_STRING_SIZE];
  int intStr = 0,intValue = 0;
  double residentMemory = 0.0;
  procinfo pinfo;
  long pageSizeInKb = sysconf(_SC_PAGE_SIZE) / 1024; /* x86-64 is configured to use 2MB pages */
  unsigned int total_memory=0;
  int index = 0;
  errno_t rc = -1;
  int proc_struct_size = sizeof(procinfo);
  for(index=0;index<(pmInfo->total_instance);index++)
  {
    rc = memset_s(&pinfo,proc_struct_size,0,proc_struct_size);
    ERR_CHK(rc);

    if( 0 == getProcPidStat(pmInfo->pid[index], &pinfo))
      return 0;
    total_memory+=pinfo.rss;
  }

  residentMemory = total_memory * pageSizeInKb;
  intStr = (int)residentMemory;
  intValue = intStr;
  if (intValue >= 1024)
    intStr = intStr/1024;
  rc = sprintf_s(retMem,sizeof(retMem),"%d%s", intStr,(intValue >= 1024) ? "m" : "k");
  if(rc < EOK)
  {
	ERR_CHK(rc);
	return 0;
  }

  rc = strncpy_s(pmInfo->memUse,sizeof(pmInfo->memUse),retMem,strlen(retMem)+1);
  if(rc != EOK)
  {
    ERR_CHK(rc);
    return 0;
  }
  return 1;
}

#if !defined(ENABLE_XCAM_SUPPORT) && !defined(ENABLE_RDKB_SUPPORT)
/**
 * @brief To get CPU info.
 *
 * @param[out] pInfo  CPU info.
 *
 * @return  Returns status of operation.
 * @retval  Return 1 on success,appropiate errorcode otherwise.
 */
int getCPUInfo(procMemCpuInfo *pInfo)
{
  int ret = 0;
  FILE *inFp = NULL;
  char command[CMD_LEN] = {'\0'};
  char var1[BUF_LEN] = {'\0'};
  char var2[BUF_LEN] = {'\0'};
  char var3[BUF_LEN] = {'\0'};           
  char var4[BUF_LEN] = {'\0'};
  char var5[BUF_LEN] = {'\0'};
  char var6[BUF_LEN] = {'\0'};           
  char var7[BUF_LEN] = {'\0'};           
  char var8[512]= {'\0'};
  char var9[512]= {'\0'}; 
  char var10[512]= {'\0'};          
  int total_cpu_usage=0;
  char top_op[2048]= {'\0'};
  int cmd_option = 0;
  errno_t rc = -1;

  if (pInfo == NULL) {

    return 0;    
  }

  /* Check Whether -c option is supported */
  ret = system(" top -c -n 1 2> /dev/null 1> /dev/null");
  if ( 0 == ret ) {
    cmd_option = 1;
  }
#ifdef INTEL
  /* Format Use:  `top n 1 | grep Receiver` */
  if ( 1 == cmd_option ) {
    rc = sprintf_s(command,sizeof(command),"top -n 1 -c | grep -v grep |grep -i '%s'", pInfo->processName);
    if(rc < EOK)
    {
      ERR_CHK(rc);
      return 0;
    }
  } else {
    rc = sprintf_s(command,sizeof(command),"top -n 1 | grep -i '%s'", pInfo->processName);
    if(rc < EOK)
    {
      ERR_CHK(rc);
      return 0;
    }
  }

#elif AMLOGIC
  if ( 1 == cmd_option ) {
    rc = sprintf_s(command,sizeof(command),"COLUMNS=1000 top -b -n 1 -c | grep -v grep | grep -i '%s'", pInfo->processName);
    if(rc < EOK)
    {
      ERR_CHK(rc);
      return 0;
    }
  } else {
    rc = sprintf_s(command,sizeof(command),"COLUMNS=1000 top -b -n 1 | grep -i '%s'", pInfo->processName);
    if(rc < EOK)
    {
      ERR_CHK(rc);
      return 0;
    }
  }

#else 
  /* ps -C Receiver -o %cpu -o %mem */
  //sprintf(command, "ps -C '%s' -o %%cpu -o %%mem | sed 1d", pInfo->processName);
  if ( 1 == cmd_option ) {
    rc = sprintf_s(command,sizeof(command),"top -b -n 1 -c | grep -v grep | grep -i '%s'", pInfo->processName);
    if(rc < EOK)
    {
      ERR_CHK(rc);
      return 0;
    }
  } else {
    rc = sprintf_s(command,sizeof(command),"top -b -n 1 | grep -i '%s'", pInfo->processName);
    if(rc < EOK)
    {
      ERR_CHK(rc);
      return 0;
    }
  }


#endif


  if(!(inFp = popen(command, "r"))){
    return 0;
  }


  //  2268 root      20   0  831m  66m  20m S   27 13.1 491:06.82 Receiver
#ifdef INTEL
  while(fgets(top_op,2048,inFp)!=NULL) {
    if(sscanf(top_op,"%s %s %s %s %s %s %s %s", var1, var2, var3, var4, var5, var6, var7, var8) == 8) {
      total_cpu_usage += atoi(var7);
      ret=1;
    }
  }
  //#endif
#else
  while(fgets(top_op,2048,inFp)!=NULL) {
    if(sscanf(top_op,"%16s %16s %16s %16s %16s %16s %16s %512s %512s %512s", var1, var2, var3, var4, var5, var6, var7, var8, var9, var10) == 10) {
      total_cpu_usage += atoi(var9);
      ret=1;
    }
  }
#endif

  rc = sprintf_s(pInfo->cpuUse,sizeof(pInfo->cpuUse),"%d", total_cpu_usage);
  if(rc < EOK)
  {
    ERR_CHK(rc);
    pclose(inFp);
    return 0;
  }
  pclose(inFp);
  return ret;

}

#else //ENABLE_XCAM_SUPPORT & ENABLE_RDKB_SUPPORT

/**
 * @brief To get total CPU time of the device.
 *
 * @param[out] totalTime   Total time of device.
 *
 * @return  Returns status of operation.
 * @retval  Return 1 on success, appropiate errorcode otherwise.
 */
int getTotalCpuTimes(int * totalTime)
{
  FILE *fp;
  long double a[10];
  int total;

  fp = fopen("/proc/stat","r");

  if(!fp)
    return 0;
  /*Coverity Fix CID:109162 CHECKED_RETURN */
  if(fscanf(fp,"%*s %Lf %Lf %Lf %Lf %Lf %Lf %Lf %Lf %Lf %Lf",
      &a[0],&a[1],&a[2],&a[3],&a[4],&a[5],&a[6],&a[7],&a[8],&a[9]) != 10 )
             LOG("Failed in fscanf()\n");
       
  fclose(fp);
  total = (a[0]+a[1]+a[2]+a[3]+a[4]+a[5]+a[6]+a[7]+a[8]+a[9]);
  *totalTime = total;

  return 1;
}

/**
 * @brief To get process CPU utilization of the process.
 *
 * @param[in]  pid            Process id.
 * @param[out] procCpuUtil    CPU utilization of process.
 *
 * @return  Returns status of operation.
 * @retval  Return 1 on success, appropiate errorcode otherwise.
 */
int getProcessCpuUtilization(int pid, float *procCpuUtil)
{
  procinfo pinfo1;
  int no_cpu;
  float total_time_process[2],time[2];
  int t[2];
  float sub1;
  float time1;
  float util=0;


  no_cpu=sysconf(_SC_NPROCESSORS_ONLN);
  if( 0 == getProcPidStat(pid, &pinfo1))
    return 0;

  total_time_process[0]= pinfo1.utime +
    pinfo1.stime +
    pinfo1.cutime +
    pinfo1.cstime;
  //start=pinfo1.starttime;

  if( !getTotalCpuTimes(&t[0]) )
    return 0;

  time[0] = t[0];
  sleep(2);

  if( 0 == getProcPidStat(pid,&pinfo1))
    return 0;

  total_time_process[1]= pinfo1.utime +
    pinfo1.stime +
    pinfo1.cutime +
    pinfo1.cstime;

  if( 0 == getTotalCpuTimes(&t[1]) )
    return 0;

  time[1] = t[1];
  sub1 = total_time_process[1]-total_time_process[0];
  time1= time[1] - time[0];
  util = (sub1/time1)*100;

  if(procCpuUtil)
    *procCpuUtil = util;
  else
    return 0;

  return 1;
}


int getCPUInfo(procMemCpuInfo *pmInfo) {
  float cpu = 0;
  float total_cpu = 0;
  int index = 0;
  errno_t rc = -1;

  for(index=0;index<(pmInfo->total_instance);index++)
  {
    if (0 == getProcessCpuUtilization(pmInfo->pid[index], &cpu))
    {
      continue;
    }
    total_cpu+=cpu;
  }

  rc = sprintf_s(pmInfo->cpuUse,sizeof(pmInfo->cpuUse),"%.1f", (float)total_cpu);
  if(rc < EOK)
  {
    ERR_CHK(rc);
    return 0;
  }
  return 1;
}

#endif //ENABLE_XCAM_SUPPORT & ENABLE_RDKB_SUPPORT

/** @} */  //END OF GROUP DCA_APIS

  /** @} */


/** @} */
/** @} */
