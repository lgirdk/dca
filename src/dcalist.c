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

#include "dcautils.h"
#include "dcalist.h"

/** @description: To insert new pattern node as first in the list
 *  @param node head, Pattern, Header, Data type, pattern count and Data
 *  @return
 */
int insertPCNode(GList **pch, char *pattern, char *header, DType_t dtype, int count, char *data)
{
  pcdata_t *new = NULL;
  int rc = -1;
  new = (pcdata_t *) malloc(sizeof(*new));
  if (NULL != new) {
    if (pattern != NULL) {
      new->pattern = (char *) malloc(strlen(pattern) + 1);
      if (NULL != new->pattern) {
        strcpy(new->pattern, pattern);
      }
    } else {
      new->pattern = NULL;
    }
    if (header != NULL) {
      new->header = (char *) malloc(strlen(header) + 1);
      if (NULL != new->header) {
        strcpy(new->header, header);
      }
    } else {
      new->header = NULL;
    }

    new->d_type = dtype;
    if (dtype == INT) {
      new->count = count;
    } else if (dtype == STR) {
      if (NULL != data) {
        new->data = (char *) malloc(strlen(data) + 1);
        if (NULL != new->data) {
          strcpy(new->data, data);
        }
      } else {
        new->data = NULL;
      }
    }

    *pch = g_list_append(*pch , new);
    rc = 0;
  }
  return rc;
}

/** @description: To do custom comparison
 *  @param node pattern, search pattern
 *  @return node on success, NULL on failure
 */
gint comparePattern(gconstpointer np, gconstpointer sp)
{
  pcdata_t *tmp = (pcdata_t *)np;
  if (tmp && tmp->pattern)
  {
    if (NULL != strstr(sp, tmp->pattern))
      return 0;
    else
      return -1;
  }
}


/** @description: To search node from the list based on the given pattern
 *  @param node head, pattern to search
 *  @return node on success, NULL on failure
 */
pcdata_t* searchPCNode(GList *pch, char *pattern)
{
  GList *fnode = NULL;
  fnode = g_list_find_custom(pch, pattern, (GCompareFunc)comparePattern);
  if (NULL != fnode)
    return fnode->data;
  else
    return NULL;
}

/** @description: Debug function to print the node
 *  @param node
 *  @return
 */
void print_pc_node(gpointer data, gpointer user_data)
{
  pcdata_t *node = (pcdata_t *)data;
  if (node) {
    LOG("node pattern:%s, header:%s", node->pattern, node->header);
    if (node->d_type == INT) {
      LOG("\tcount:%d", node->count);
    } else if (node->d_type == STR) {
      LOG("\tdata:%s", node->data);
    }
  }
}

/** @description: Debug function to print all the nodes in the list
 *  @param node head
 *  @return
 */
void printPCNodes(GList *pch)
{
  g_list_foreach(pch, (GFunc)print_pc_node, NULL);
}

/** @description: Delete a node
 *  @param node head
 *  @return
 */
 void freePCNode(gpointer node)
{
  pcdata_t *tmp = (pcdata_t *)(node);
  if (NULL != tmp)
  {
    if (NULL != tmp->pattern) {
      free(tmp->pattern);
      tmp->pattern = NULL;
    }
    if (NULL != tmp->header) {
      free(tmp->header);
      tmp->header = NULL;
    }
    if (tmp->d_type == STR) {
      if (NULL != tmp->data) {
        free(tmp->data);
        tmp->data = NULL;
      }
    }
    free(tmp);
  }
}

/** @description: Delete/Clear all the nodes in the list
 *  @param node head
 *  @return
 */
void clearPCNodes(GList **pch)
{
  g_list_free_full(*pch, &freePCNode);
}
