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
#include <unistd.h>
#include <ctype.h>

#include "glib.h"
#include "cJSON.h"

#include "dcautils.h"
#include "dcalist.h"

char *PERSISTENT_PATH = NULL;
char *LOG_PATH = NULL;
char *DEVICE_TYPE = NULL;
cJSON *SEARCH_RESULT_JSON = NULL, *ROOT_JSON = NULL;
int CUR_EXEC_COUNT = 0;
long LAST_SEEK_VALUE = 0;

/** @description: Process the top_log.txt patterns (Load average and process usage)
 *  @param logfile name, node head, node count
 *  @return
 */
int processTopPattern(char *logfile, GList *pchead, int pcIndex)
{
  GList *tlist = pchead;
  pcdata_t *tmp = NULL;
  while (NULL != tlist) {
    tmp = tlist->data;
    if (NULL != tmp) {
        if ((NULL != tmp->header) && (NULL != strstr(tmp->header, "Load_Average"))) {
          if (0 == getLoadAvg()) {
            LOG("getLoadAvg() Failed with error");
          }
        } else {
          if (NULL != tmp->pattern) {
            getProcUsage(tmp->pattern);
          }
       }
    }
    tlist = g_list_next(tlist);
  }
  return 0;
}

int addToJson(GList *pchead)
{
  GList *tlist = pchead;
  pcdata_t *tmp = NULL;
  while (NULL != tlist) {
    tmp = tlist->data;
    if (NULL != tmp) {
        if (tmp->pattern)
        {
          if (tmp->d_type == INT) {
            if (tmp->count != 0) {
              char tmp_str[5] = {0};
              sprintf(tmp_str, "%d", tmp->count);
              addToSearchResult(tmp->header, tmp_str);
            }
          } else if(tmp->d_type == STR) {
            if (NULL != tmp->data && (strcmp(tmp->data, "0") != 0)) {
              addToSearchResult(tmp->header, tmp->data);
            }
          }
        }
    }
    tlist = g_list_next(tlist);
  }
}

/** @description: Process pattern if it has split text in the header
 *  @param log file matched line, node
 *  @return -1 on failure, 0 on success
 */
int getIPVideo(char *line, pcdata_t *pcnode)
{
  char *strFound = NULL;
  strFound = strstr(line, pcnode->pattern);

  if (strFound != NULL ) {
    int tlen = 0, plen = 0;
    if (NULL == pcnode->data) {
      pcnode->data = (char *) malloc(MAXLINE);
    }
    if (NULL == pcnode->data) {
      return (-1);
    }
    tlen = (int)strlen(line);
    plen = (int)strlen(pcnode->pattern);

    strncpy (pcnode->data, (strFound+strlen(pcnode->pattern)), tlen-plen);
    pcnode->data[tlen-plen] = '\0'; //For Boundary Safety
  }
  return 0;
}

/** @description: To get RDK error code from the string
 *  @param source string, error code out
 *  @return
 */
int getErrorCode(char *str, char *ec)
{
  int i = 0, j = 0, len = strlen(str);
  char tmpEC[LEN] = {0};
  while (str[i] != '\0') {
    if (len >=4 && str[i] == 'R' && str[i+1] == 'D' && str[i+2] =='K' && str[i+3] == '-') {
      i += 4;
      j = 0;
      if (str[i] == '0' || str[i] == '1') {
        tmpEC[j] = str[i];
        i++; j++;
        if (str[i] == '0' || str[i] == '3') {
          tmpEC[j] = str[i];
          i++; j++;
          if (0 != isdigit(str[i])) {
            while (i<=len && 0 != isdigit(str[i]) && j<RDK_EC_MAXLEN) {
              tmpEC[j] = str[i];
              i++; j++;
              ec[j] = '\0';
              strcpy(ec, tmpEC);
            }
            break;
          }
        }
      }
    }
    i++;
  }
  return 0;
}


/** @description: To handle RDK Error codes from the log file
 *  @param log file
 *  @return -1 on failure, 0 on success
 */
int handleRDKErrCodes(GList **rdkec_head, char *line)
{
  char err_code[20] = {0}, rdkec[20] = {0};
  pcdata_t *tnode = NULL;

  getErrorCode(line, err_code);
  if (strcmp(err_code, "") != 0) {
    strcpy(rdkec, "RDK-");
    strcat(rdkec, err_code);
    tnode = searchPCNode(*rdkec_head, rdkec);
    if (NULL != tnode) {
      tnode->count++;
    } else {
      /* Args:  GList **pch, char *pattern, char *header, DType_t dtype, int count, char *data */
      insertPCNode(rdkec_head, rdkec, rdkec, INT, 1, NULL);
    }
    return 0;
  }
  return -1;
}


/** @description: Process pattern count (loggrep)
 *  @param log file, node head, node count
 *  @return -1 on failure, 0 on success
 */
int processCountPattern(char *logfile, GList *pchead, int pcIndex, GList **rdkec_head)
{
  char temp[MAXLINE];

  while (getsRotatedLog(temp, MAXLINE, logfile) != NULL ) {
    int len = strlen(temp);
    if (len > 0 && temp[len-1] == '\n')
      temp[--len] = '\0';
    pcdata_t *pc_node = searchPCNode(pchead, temp);
    if (NULL != pc_node) {
      if (pc_node->d_type == INT) {
        pc_node->count++;
      } else {
        if (NULL != pc_node->header) {
          if (NULL != strstr(pc_node->header, "split")) {
            getIPVideo(temp, pc_node);
          }
        }
      }
    } else {
      if (NULL != strstr(temp, "RDK-")) {
        handleRDKErrCodes(rdkec_head, temp);
      }
    }
    usleep(USLEEP_SEC);
  }
  return 0;
}

/** @description: Generic pattern function based on pattern to call top/count
 *  @param Previous log file out, current log file, node head, node count
 *  @return
 */
int processPattern(char **prev_file, char *logfile, GList **rdkec_head, GList *pchead, int pcIndex)
{
  if (NULL != logfile) {

    if ((NULL == *prev_file) || (strcmp(*prev_file, logfile) != 0)) {
      if (NULL == *prev_file) {
        *prev_file = malloc(strlen(logfile) + 1);
      } else {
        char *tmp = NULL;
        writeLogSeek(*prev_file, LAST_SEEK_VALUE);
        tmp = realloc(*prev_file, strlen(logfile) + 1);
        if (NULL != tmp) {
          *prev_file = tmp;
        } else {
          free(*prev_file);
          *prev_file = NULL;
        }
      }

      if (NULL != *prev_file) {
        strcpy(*prev_file, logfile);
      }
    }

    // Process
    if (NULL != pchead) {
      if (0 == strcmp(logfile, "top_log.txt")) {
        processTopPattern(logfile, pchead, pcIndex);
      } else {
        processCountPattern(logfile, pchead, pcIndex, rdkec_head);
        addToJson(pchead);
      }
    }

    // clear nodes memory after process
    // printPCNodes(pchead);
    clearPCNodes(&pchead);
  }
  return 0;
}


/** @description: Function like strstr but based on the string delimiter
 *  @param string, delimiter
 *  @return first string based on delimiter in first call and goes on, NULL at the end
 */
char *strSplit(char *str, char *delim) {
  static char *next_str;
  char *last = NULL;

  if (NULL != str) {
    next_str = str;
  }

  if (NULL == next_str) {
    return next_str;
  }

  last = strstr(next_str, delim);
  if (NULL == last) {
    char *ret = next_str;
    next_str = NULL;
    return ret;
  }

  char *ret = next_str;
  *last = '\0';
  next_str = last + strlen(delim);
  return ret;
}

/** @description: To get node data type based on the pattern
 *  @param filename, header and data type out
 *  @return
 */
int getDType(char *filename, char *header, DType_t *dtype)
{
  if (NULL != header) {
    if (NULL != strstr(header, "split")) {
      *dtype = STR;
    } else if (0 == strcmp(filename, "top_log.txt")) {
      *dtype = STR;
    } else {
      *dtype = INT;
    }
  }
}

/** @description: Main logic function to parse sorted file and to process the pattern list
 *  @param filename
 *  @return -1 on failure, 0 on success
 */
int parseFile(char *fname)
{
  FILE *sfp = NULL;
  char line[MAXLINE];
  char *filename = NULL, *prevfile = NULL;
  int pcIndex = 0;
  GList *pchead = NULL, *rdkec_head = NULL;

  if (NULL == (sfp = fopen(fname, "r"))) {
    return (-1);
  }

  while (NULL != fgets(line, MAXLINE, sfp)) {
    // Remove new line
    int len = strlen(line);
    if (len > 0 && line[len-1] == '\n')
      line[--len] = '\0';

    // multiple string split
    char *temp_header = strSplit(line, DELIMITER);
    char *temp_pattern = strSplit(NULL, DELIMITER);
    char *temp_file = strSplit(NULL, DELIMITER);
    char *temp_skip_interval = strSplit(NULL, DELIMITER);
    int tmp_skip_interval, is_skip_param;
    DType_t dtype;

    if (NULL == temp_file || NULL == temp_pattern || NULL == temp_header || NULL == temp_skip_interval)
      continue;

    //LOG(">l:%s,f:%s,p:%s<", line, temp_file, temp_pattern);
    if ((0 == strcmp(temp_pattern, "")) || (0 == strcmp(temp_file, "")))
      continue;

    if (0 == strcasecmp(temp_file, "snmp"))
      continue;

    getDType(temp_file, temp_header, &dtype);
    tmp_skip_interval = atoi(temp_skip_interval);

    if (tmp_skip_interval <= 0)
      tmp_skip_interval = 0;

    is_skip_param = isSkipParam(tmp_skip_interval);

    if (NULL == filename) {
      filename = malloc(strlen(temp_file) + 1);
      pchead = NULL;
      if (is_skip_param == 0 && (0 == insertPCNode(&pchead, temp_pattern, temp_header, dtype, 0, NULL))) {
        pcIndex = 1;
      }
    } else {
      if ((0 == strcmp(filename, temp_file)) && pcIndex <= MAX_PROCESS ) {
        if (is_skip_param == 0 && (0 == insertPCNode(&pchead, temp_pattern, temp_header, dtype, 0, NULL))) {
          pcIndex++;
        }
      } else {
        char *tmp = NULL;
        processPattern(&prevfile, filename, &rdkec_head, pchead, pcIndex);
        pchead = NULL;
        tmp = realloc(filename, strlen(temp_file) + 1);
        if (NULL != tmp) {
          filename = tmp;
        } else {
          free(filename);
          filename = NULL;
        }
        if (is_skip_param == 0 && (0 == insertPCNode(&pchead, temp_pattern, temp_header, dtype, 0, NULL))) {
          pcIndex = 1;
        }
      }
    }
    if (NULL != filename) {
      strcpy(filename, temp_file);
    }
    usleep(USLEEP_SEC);
  }
  processPattern(&prevfile, filename, &rdkec_head, pchead, pcIndex);
  writeLogSeek(filename, LAST_SEEK_VALUE);
  pchead = NULL;

  /* max limit not maintained for rdkec_head FIXME */
  if (NULL != rdkec_head) {
    addToJson(rdkec_head);
    // clear nodes memory after process
    clearPCNodes(&rdkec_head);
    rdkec_head = NULL;
  }

  addToSearchResult("<remaining_keys>", "<remaining_values>");

  if (NULL != filename)
    free(filename);

  if (NULL != prevfile)
    free(prevfile);

  fclose(sfp);
  return 0;
}

/** @description: main function
 *  @param command line arguments (Expected: sorted file)
 *  @return parseFile() function return code
 */
int main(int argc, char *argv[]) {
  char *fname = argv[1];
  int rc = -1;
  if (NULL != fname) {
    LOG("Conf File =  %s ", fname);
    updateConfVal();
    updateExecCounter();
    initSearchResultJson(&ROOT_JSON, &SEARCH_RESULT_JSON);
    rc = parseFile(fname);
    printJson(ROOT_JSON);
    clearSearchResultJson(&ROOT_JSON);
    clearConfVal();
  }
  return rc;
}


/** @} */


/** @} */
/** @} */
