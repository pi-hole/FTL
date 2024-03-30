/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API JSON macros
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "webserver/cJSON/cJSON.h"
// logging routines
#include "log.h"

#define JSON_NEW_OBJECT() cJSON_CreateObject()
#define JSON_NEW_ARRAY() cJSON_CreateArray()

#define JSON_ADD_ITEM_TO_ARRAY(array, item) cJSON_AddItemToArray(array, item)

#define JSON_COPY_STR_TO_OBJECT(object, key, string)({ \
	cJSON *string_item = NULL; \
	if(string != NULL) \
	{ \
		string_item = cJSON_CreateString((const char*)(string)); \
	} \
	else \
	{ \
		string_item = cJSON_CreateNull(); \
	} \
	if(string_item == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_internal_error(api); \
		log_err("JSON_COPY_STR_TO_OBJECT FAILED (key: \"%s\", string: \"%s\")!", key, string); \
		return 500; \
	} \
	cJSON_AddItemToObject(object, key, string_item); \
})

#define JSON_REF_STR_IN_OBJECT(object, key, string)({ \
	cJSON *string_item = NULL; \
	if(string != NULL) \
	{ \
		string_item = cJSON_CreateStringReference((const char*)(string)); \
	} \
	else \
	{ \
		string_item = cJSON_CreateNull(); \
	} \
	if(string_item == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_internal_error(api); \
		log_err("JSON_REF_STR_IN_OBJECT FAILED (key: \"%s\", string: \"%s\")!", key, string); \
		return 500; \
	} \
	cJSON_AddItemToObject(object, key, string_item); \
})

#define JSON_ADD_NUMBER_TO_OBJECT(object, key, num)({ \
	const double number = num; \
	if(cJSON_AddNumberToObject(object, key, number) == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_internal_error(api); \
		log_err("JSON_ADD_NUMBER_TO_OBJECT FAILED!"); \
		return 500; \
	} \
})

#define JSON_ADD_NULL_TO_OBJECT(object, key)({\
	cJSON *null_item = cJSON_CreateNull(); \
	if(null_item == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_internal_error(api); \
		log_err("JSON_ADD_NULL_TO_OBJECT FAILED!"); \
		return 500; \
	} \
	cJSON_AddItemToObject(object, key, null_item); \
})

#define JSON_ADD_BOOL_TO_OBJECT(object, key, val)({\
	const cJSON_bool var_val = val; \
	cJSON *bool_item = cJSON_CreateBool(var_val); \
	if(bool_item == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_internal_error(api); \
		log_err("JSON_ADD_BOOL_TO_OBJECT FAILED!"); \
		return 500; \
	} \
	cJSON_AddItemToObject(object, key, bool_item); \
})

#define JSON_ADD_NUMBER_TO_ARRAY(object, num)({ \
	const double number = num; \
	cJSON *number_item = cJSON_CreateNumber(number); \
	cJSON_AddItemToArray(object, number_item); \
})

#define JSON_REPLACE_NUMBER_IN_ARRAY(object, index, num)({ \
	const double number = num; \
	cJSON *number_item = cJSON_CreateNumber(number); \
	cJSON_ReplaceItemInArray(object, index, number_item); \
})

#define JSON_ADD_BOOL_TO_ARRAY(object, val)({ \
	const cJSON_bool var_val = val; \
	cJSON *bool_item = cJSON_CreateBool(var_val); \
	cJSON_AddItemToArray(object, bool_item); \
})

#define JSON_REF_STR_IN_ARRAY(array, string)({ \
	cJSON *string_item = NULL; \
	if(string != NULL) \
	{ \
		string_item = cJSON_CreateStringReference((const char*)(string)); \
	} \
	else \
	{ \
		string_item = cJSON_CreateNull(); \
	} \
	if(string_item == NULL) \
	{ \
		cJSON_Delete(array); \
		send_http_internal_error(api); \
		log_err("JSON_REF_STR_IN_ARRAY FAILED!"); \
		return 500; \
	} \
	cJSON_AddItemToArray(array, string_item); \
})

#define JSON_COPY_STR_TO_ARRAY(array, string)({ \
	cJSON *string_item = NULL; \
	if(string != NULL) \
	{ \
		string_item = cJSON_CreateString((const char*)(string)); \
	} \
	else \
	{ \
		string_item = cJSON_CreateNull(); \
	} \
	if(string_item == NULL) \
	{ \
		cJSON_Delete(array); \
		send_http_internal_error(api); \
		log_err("JSON_COPY_STR_TO_ARRAY FAILED!"); \
		return 500; \
	} \
	cJSON_AddItemToArray(array, string_item); \
})

// cJSON_AddItemToObject() does not return anything
// Note that this operation transfers the ownership of the added item to the
// new parent so that when that array or object is deleted, it gets deleted as well.
#define JSON_ADD_ITEM_TO_OBJECT(object, key, item) cJSON_AddItemToObject(object, key, item)

#define JSON_ADD_NULL_IF_NOT_EXISTS(object, key)({ \
	if(cJSON_GetObjectItemCaseSensitive(object, key) == NULL) \
	{ \
		cJSON_AddNullToObject(object, key); \
	} \
})

#define JSON_DELETE(object) cJSON_Delete(object)

#define JSON_SEND_OBJECT(object)({ \
	cJSON_AddNumberToObject(object, "took", double_time() - api->now);\
	char *json_string = json_formatter(object); \
	if(json_string == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_internal_error(api); \
		log_err("JSON_SEND_OBJECT FAILED!"); \
		return 500; \
	} \
	send_http(api, "application/json; charset=utf-8", json_string); \
	cJSON_free(json_string); \
	cJSON_Delete(object); \
	return 200; \
})

#define JSON_SEND_OBJECT_UNLOCK(object)({ \
	cJSON_AddNumberToObject(object, "took", double_time() - api->now);\
	char *json_string = json_formatter(object); \
	if(json_string == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_internal_error(api); \
		log_err("JSON_SEND_OBJECT FAILED!"); \
		unlock_shm(); \
		return 500; \
	} \
	send_http(api, "application/json; charset=utf-8", json_string); \
	cJSON_free(json_string); \
	cJSON_Delete(object); \
	unlock_shm(); \
	return 200; \
})

#define JSON_SEND_OBJECT_CODE(object, code)({ \
	if((code) != 204) \
	{ \
		cJSON_AddNumberToObject(object, "took", double_time() - api->now); \
	} \
	char *json_string = json_formatter(object); \
	if(json_string == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_internal_error(api); \
		log_err("JSON_SEND_OBJECT_CODE FAILED!"); \
		return 500; \
	} \
	send_http_code(api, "application/json; charset=utf-8", code, json_string); \
	cJSON_free(json_string); \
	cJSON_Delete(object); \
	return code; \
})
/*
#define JSON_SEND_OBJECT_AND_HEADERS(object, additional_headers)({ \
	char *json_string = json_formatter(object); \
	if(json_string == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_internal_error(api); \
		log_err("JSON_SEND_OBJECT_AND_HEADERS FAILED!"); \
		return 500; \
	} \
	send_http(api, "application/json; charset=utf-8", additional_headers, json_string); \
	cJSON_free(json_string); \
	cJSON_Delete(object); \
	free(additional_headers); \
	return 200; \
})

#define JSON_SEND_OBJECT_AND_HEADERS_CODE(object, code, additional_headers)({ \
	char *json_string = json_formatter(object); \
	if(json_string == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_internal_error(api); \
		log_err("JSON_SEND_OBJECT_AND_HEADERS_CODE FAILED!"); \
		return 500; \
	} \
	send_http_code(api, "application/json; charset=utf-8", additional_headers, code, json_string); \
	cJSON_free(json_string); \
	cJSON_Delete(object); \
	free(additional_headers); \
	return code; \
})
*/

#define JSON_INCREMENT_NUMBER(number_obj, inc)({ \
	cJSON_SetNumberHelper(number_obj, number_obj->valuedouble + inc); \
})

// Returns true if the key exists and is true, otherwise false
#define JSON_KEY_TRUE(obj, key)({ \
	cJSON *elem = cJSON_GetObjectItemCaseSensitive(obj, key); \
	elem != NULL ? cJSON_IsTrue(elem) : false; \
})
