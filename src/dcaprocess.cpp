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


#include <iostream>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>           /* Definition of AT_* constants */
#include <unistd.h>
#include <unistd.h>
#include <math.h>
#include <ios>
#include <fstream>
#include <string>
#include <cstring>
#include <cstdlib>

#define LEN 14
#define BUF_LEN 16
#define CMD_LEN 256
#define MAXLEN 512
#define PID_SIZE 10
#define PIDOF_SIZE 50
#define MEM_STRING_SIZE 20
#define PROC_PATH_SIZE 50

using namespace std;


#ifndef ENABLE_XCAM_SUPPORT

typedef struct _procMemCpuInfo {
    char processName[BUF_LEN];
    char cpuUse[BUF_LEN];
    char memUse[BUF_LEN];
} procMemCpuInfo;


bool getProcInfo(procMemCpuInfo *pInfo);

int main(int argc,char *argv[]) {
    FILE *in = NULL;
    char *processName = NULL;
    FILE *fp = NULL ;
    procMemCpuInfo pInfo;

    memset(&pInfo, '\0', sizeof(procMemCpuInfo));
    
    if(argv[1] == NULL)
    {
       return 0;
    }
	
    processName = argv[1];
 
    if (processName != NULL) {  
        memcpy(pInfo.processName, processName, strlen(processName)+1); 
    }


   
    if(false == getProcInfo(&pInfo))
    {
        cout << "{\"Failed\":\"0\"}";
	    return 0;
    }
	
    cout << "{\"mem_" << processName << "\":\"" << pInfo.memUse << "\"},";
    cout << "{\"cpu_" << processName << "\":\"" << pInfo.cpuUse << "\"}";

    return 1;
}

/**
 * @addtogroup DCA_APIS
 * @{
 */


/**
 * @brief To get the reserve memory of a given process in pages.
 *
 * @param[in] pInfo           Process Name.
 * @param[in] processPid      Process Id.
 *
 * @return Returns reserve memory of the requested process.
 */
char* getResidentMemory(procMemCpuInfo *pInfo, int* processPid)
{
   using std::ios_base;
   using std::ifstream;
   using std::string;
   char procPath[PROC_PATH_SIZE];
   static char retMem[MEM_STRING_SIZE];
   int intStr = 0,intValue = 0;
   long pageSizeInKb = sysconf(_SC_PAGE_SIZE) / 1024; /* x86-64 is configured to use 2MB pages */

   /* Use /proc/<pid>/statm (see man page for proc)
    * statm is made up of size, resident, shared, text, lib, data
    * and dt columns.
    * We only require resident memory, so read the 1st 2 columns.
    */
   /* Set procPath */
   sprintf (procPath, "/proc/%d/statm", *processPid);

   ifstream statm(procPath);
   int totalMemory, residentMemory;
   statm >> totalMemory >> residentMemory;
   statm.close();

   residentMemory *= pageSizeInKb;
   intStr = (int)residentMemory;
   intValue = intStr;
   if (intValue >= 1024)
      intStr = intStr/1024;
   snprintf(retMem, sizeof(retMem), "%d", intStr);
   if (intValue >= 1024)
      strcat(retMem,"m");
   else
      strcat(retMem,"k");
   return retMem;
}

bool getProcInfo(procMemCpuInfo *pInfo)
{
    bool ret = false;
    FILE *inFp = NULL;
    char command[CMD_LEN] = {'\0'};
    char *pcpu = NULL, *pmem = NULL;
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
    int pid = 0;

    if (pInfo == NULL) {

        return false;    
    }

    sprintf(command, "pidof %s", pInfo->processName);
    if(!(inFp = popen(command, "r"))){
        return false;
    }
    fscanf(inFp,"%d",&pid);
    pclose(inFp);
    if( pid == 0) {
        return false;
    }

#ifdef INTEL
    #ifdef YOCTO_BUILD
        /* Format Use:  `top -b -n 1 | grep Receiver` */
        sprintf(command, "top -b -n 1 | sed  's/^[ \t]*//' | grep \"^%d\"", pid);
    #else
        /* Format Use:  `top -n 1 | grep Receiver` */
        sprintf(command, "top -n 1 | grep -i '%s'", pInfo->processName);
    #endif

#else 
     /* ps -C Receiver -o %cpu -o %mem */
    //sprintf(command, "ps -C '%s' -o %%cpu -o %%mem | sed 1d", pInfo->processName);
    sprintf(command, "top -b -n 1 | grep -i '%s'", pInfo->processName);

#endif

   
    if(!(inFp = popen(command, "r"))){
        return false;
    }


 //  2268 root      20   0  831m  66m  20m S   27 13.1 491:06.82 Receiver
#ifdef INTEL
    if (fscanf(inFp,"%s %s %s %s %s %s %s %s", var1, var2, var3, var4, var5, var6, var7, var8) == 8) {                           
        pcpu = var7;
	}
//#endif
#else
//while(fscanf(inFp,"%s %s", var1, var2) == 2)
//    {
//	    pcpu = var1;
//	    pmem = var2;
 //   }
  if (fscanf(inFp,"%s %s %s %s %s %s %s %s %s %s", var1, var2, var3, var4, var5, var6, var7, var8, var9, var10) == 10) {                           
        pcpu = var9;
	}
#endif
    /* Get the resident memory value. Take from proc/$pid/stats */
    pmem = getResidentMemory(pInfo, &pid);

    if ((pcpu != NULL) && (pmem != NULL)) {
        strncpy(pInfo->cpuUse, pcpu, strlen(pcpu)+1);
        strncpy(pInfo->memUse, pmem, strlen(pmem)+1);
        ret = true;
    }
    
    pclose(inFp);
    return ret;

}
#else //ENABLE_XCAM_SUPPORT
typedef struct proc_info {
  /* See man page for proc for details of fields. */
  int           utime;
  int           stime;
  int           cutime;
  int           cstime;
  unsigned int  rss;
} procinfo;

/**
 * @brief To get process information of the process.
 *
 * @param[in] pid        Process Id of process.
 * @param[in] pinfo      Address of process object of process.
 *
 * @return  Returns status of operation.
 * @retval  True on success.
 */
bool getProcInfo(int pid, procinfo * pinfo)
{
	char szFileName [CMD_LEN],szStatStr [2048],*s, *t;
	FILE *fp;
	struct stat st;
	int ppid, pgrp, session, tty, tpgid, counter, priority, starttime, signal, blocked, sigignore, sigcatch;
	char exName [CMD_LEN], state;
	unsigned euid, egid;
	unsigned int flags, minflt, cminflt, majflt, cmajflt, timeout, itrealvalue, vsize, rlim, startcode, endcode, startstack, kstkesp, kstkeip, wchan, rss; 

	if (NULL == pinfo)
	{
		cout << "Invalid input(pinfo=NULL) to get process info"<<endl;
		return false;
	}

	sprintf (szFileName, "/proc/%u/stat", (unsigned) pid);

	if (-1 == access (szFileName, R_OK))
	{
		cout << "Unable to access file in get proc info"<<endl;
		return false;
	}

	if (-1 != stat (szFileName, &st))
	{
		euid = st.st_uid;
		egid = st.st_gid;
	} 
	else
	{
	euid = egid = -1;
	}

	if ((fp = fopen (szFileName, "r")) == NULL)
	{
		cout << "Failed to open file in get process info"<<endl; 
		return false;
	}

	if ((s = fgets (szStatStr, 2048, fp)) == NULL)
	{
		fclose (fp);
	}

	/** pid **/
	s = strchr (szStatStr, '(') + 1;
	t = strchr (szStatStr, ')');
	strncpy (exName, s, t - s);
	exName [t - s] = '\0';

	/* Refer to /proc/[pid]/stat from proc man-page.*/
	sscanf (t + 2, "%c %d %d %d %d %d %u %u %u %u %u %d %d %d %d %d %d %u %u %d %u %u %u %u %u %u %u %u %d %d %d %d %u",
	/*       1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33*/
		&(state), &(ppid), &(pgrp), &(session), &(tty), &(tpgid), &(flags),
		&(minflt), &(cminflt), &(majflt), &(cmajflt), &(pinfo->utime),
		&(pinfo->stime), &(pinfo->cutime), &(pinfo->cstime), &(counter),
		&(priority), &(timeout), &(itrealvalue), &(starttime),
		&(vsize), &(pinfo->rss), &(rlim), &(startcode), &(endcode),
		&(startstack), &(kstkesp), &(kstkeip), &(signal), &(blocked),
		&(sigignore), &(sigcatch), &(wchan));

	fclose (fp);

	return true;
}

/**
 * @brief To get total CPU time of the device.
 *
 * @param[in] totalTime    Total time of device.
 *
 * @return  Returns status of operation.
 * @retval  True on success.
 */
int getTotalCpuTimes(int * totalTime)
{
	FILE *fp;
	long double a[10];
	int total;

	fp = fopen("/proc/stat","r");

	if(!fp)
	return false;

	fscanf(fp,"%*s %Lf %Lf %Lf %Lf %Lf %Lf %Lf %Lf %Lf %Lf",
		&a[0],&a[1],&a[2],&a[3],&a[4],&a[5],&a[6],&a[7],&a[8],&a[9]);
	fclose(fp);
	total = (a[0]+a[1]+a[2]+a[3]+a[4]+a[5]+a[6]+a[7]+a[8]+a[9]);
	*totalTime = total;

	return true;
}

/**
 * @brief To get process CPU utilization of the process.
 *
 * @param[in] pid              Process id of process.
 * @param[in] procCpuUtil      Process cpu utilization of process.
 *
 * @return  Returns status of operation.
 * @retval  True on success.
 */
bool getProcessCpuUtilization(int pid, float *procCpuUtil)
{
	char cpuUtilizationProc[MAXLEN]={'\0'};
	procinfo pinfo1;
	int no_cpu;
	float total_time_process[2],time[2];
	int t[2];
	float sub1;
	float time1;
    float util=0;


	no_cpu=sysconf(_SC_NPROCESSORS_ONLN);
	if( false == getProcInfo(pid, &pinfo1))
	return false;

	total_time_process[0]= pinfo1.utime +
				pinfo1.stime +
				pinfo1.cutime +
				pinfo1.cstime;
	//start=pinfo1.starttime;

	if( !getTotalCpuTimes(&t[0]) )
		return false;

	time[0] = t[0];
	sleep(2);

	if( false == getProcInfo(pid,&pinfo1))
		return false;

	total_time_process[1]= pinfo1.utime +
				pinfo1.stime +
				pinfo1.cutime +
				pinfo1.cstime;

	if( false == getTotalCpuTimes(&t[1]) )
		return false;

	time[1] = t[1];
	sub1 = total_time_process[1]-total_time_process[0];
	time1= time[1] - time[0];
	//util = (sub1/time1)*100*no_cpu;
	util = (sub1/time1)*100;

	// round off to 2 decimal points
	util = roundf(util * 100)/100;

	if(procCpuUtil)
		*procCpuUtil = util;
	else
		return false;

	return true;

}


int main(int argc,char *argv[]) {
    char *processName = NULL;
    procinfo pInfo;
    char command[CMD_LEN] = {'\0'};
    int pid = 0;
    float cpu = 0.0;
    FILE *inFp = NULL;
    int pagesize_kb = 0;

    memset(&pInfo, 0, sizeof(procinfo));
    
    if(argv[1] == NULL)
    {
       cout<<"No Arguments passed!"<<endl;
       return false;
    }
	
    processName = argv[1];
    sprintf(command, "pidof %s", processName);

    if(!(inFp = popen(command, "r"))){
        return false;
    }

    fscanf(inFp,"%d",&pid);
    pclose(inFp);

    if(pid)
    {
        if(false == getProcInfo(pid,&pInfo))
        {
            cout << "{\"Failed\":\"0\"}";
	    return false;
        }
    }
    else
    {
        return false;
    }

    getProcessCpuUtilization(pid,&cpu);

    pagesize_kb = getpagesize()/1024;
    cout << "{\"mem_" << processName << "\":\"" << (pInfo.rss) * pagesize_kb << "\"},";
    cout << "{\"cpu_" << processName << "\":\"" << cpu << "\"}";

    return true;
}


#endif //ENABLE_XCAM_SUPPORT

/** @} */  //END OF GROUP DCA_APIS

/** @} */


/** @} */
/** @} */
