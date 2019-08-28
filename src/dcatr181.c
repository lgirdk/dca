#include <stdio.h>
#include <string.h>
/* ccsp message bus header includes */
#include <pthread.h>
#include "ccsp_base_api.h"
#include "ccsp_message_bus.h"
#include "ccsp_memory.h"

#include "dcatr181.h"
#include "dcautils.h"

/* Enable debug prints */
//#define TR181_DEBUG
#ifdef TR181_DEBUG
#define print_message(...) LOG(__VA_ARGS__)
#else
#define print_message
#endif


/**
 * @addtogroup DCA_TYPES
 * @{
 */

#define CCSP_BUS_CLIENT "ccsp.busclient"
#define CCSP_BUS_CFG  CCSP_MSG_BUS_CFG /* OR /tmp/ccsp_msg.cfg */
#define DST_COMP_CR "com.cisco.spvtg.ccsp.CR"
#define DST_COMP_SUBSYS "eRT."
#define DST_COMP_ID DST_COMP_SUBSYS DST_COMP_CR /* eRT.com.cisco.spvtg.ccsp.CR */

/* @} */ // End of group DCA_TYPES

void *ccsp_bus_handle = NULL;

/**
 * @addtogroup DCA_APIS
 * @{
 */

/**
 * @brief This API initalizes the ccsp message bus.
 *
 * @return  Returns status of operation.
 * @retval  Returns zero on success, appropiate errorcode otherwise.
 */
int ccsp_handler_init()
{
   int ret = 0;

   if ( NULL == ccsp_bus_handle )
   {
       ret = CCSP_Message_Bus_Init(CCSP_BUS_CLIENT, CCSP_BUS_CFG, &ccsp_bus_handle, Ansc_AllocateMemory_Callback, Ansc_FreeMemory_Callback);
       if ( 0 != ret )
       {
           print_message("[%s]:CCSP_Message_Bus_Init() failed ret_val = %d\n", __FUNCTION__, ret);
           ccsp_bus_handle = NULL;
           return 1;
       }
   }

   return ret;
}

/**
 * @brief This API is to uninitialize message bus.
 */
void ccsp_handler_exit()
{
    CCSP_Message_Bus_Exit(ccsp_bus_handle);
    ccsp_bus_handle = NULL;
}

/**
 * @brief This API is to retrieve the value of TR181 telemetry. 
 *
 * @return  Returns status of operation.
 * @retval  Returns zero on success, appropiate errorcode otherwise.
 */
int get_tr181param_value( const char* path_namespace, char* parm_value, int len)
{
    int ret = 0;
    int comp_size = 0;
    int val_size = 0;
    char* dst_pathname = NULL;
    char* dst_compid = NULL;
    char* parameter_name[1] = {NULL};
    parameterValStruct_t** param_val = NULL;
    componentStruct_t** components = NULL;

    if( NULL == ccsp_bus_handle  || NULL == path_namespace || NULL == parm_value)
    {
        print_message("[%s]:Invalid input arguments\n", __FUNCTION__);
        return 1;
    }

    /* Get dest component id and path */
    ret = CcspBaseIf_discComponentSupportingNamespace(ccsp_bus_handle, DST_COMP_ID, path_namespace, DST_COMP_SUBSYS, &components, &comp_size);
    if ( CCSP_SUCCESS != ret || 1 > comp_size )
    {
        print_message("[%s]:Unable to find the destination component namespace ret_val = %d comp_size = %d\n", __FUNCTION__, ret, comp_size);
        return 1;
    }

    dst_compid = components[0]->componentName;
    dst_pathname = components[0]->dbusPath;
    parameter_name[0] = path_namespace;

    /* Get values of tr181 object */
    ret = CcspBaseIf_getParameterValues(ccsp_bus_handle, dst_compid, dst_pathname, parameter_name, 1, &val_size, &param_val);
    if( CCSP_SUCCESS != ret || 1 > val_size )
    {
         print_message("[%s]:Unable get param values ret_val = %d size = %d\n", __FUNCTION__, ret, val_size);
         free_componentStruct_t(ccsp_bus_handle, comp_size, components);
        return 1;
    }

    snprintf(parm_value, (len - 1), "%s",  param_val[0]->parameterValue);
    free_componentStruct_t(ccsp_bus_handle, comp_size, components);
    free_parameterValStruct_t(ccsp_bus_handle, val_size, param_val);
    
    return 0;
}

/** @} */  //END OF GROUP DCA_APIS
