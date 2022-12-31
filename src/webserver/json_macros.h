/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API JSON macros
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../cJSON/cJSON.h"
// logging routines
#include "../log.h"

#define JSON_NEW_OBJECT() cJSON_CreateObject();
#define JSON_NEW_ARRAY() cJSON_CreateArray();

#define JSON_ADD_ITEM_TO_ARRAY(array, item) cJSON_AddItemToArray(array, item);

#define JSON_COPY_STR_TO_OBJECT(object, key, string){ \
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
}

#define JSON_REF_STR_IN_OBJECT(object, key, string){ \
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
}

#define JSON_ADD_NUMBER_TO_OBJECT(object, key, num){ \
	const double number = num; \
	if(cJSON_AddNumberToObject(object, key, number) == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_internal_error(api); \
		log_err("JSON_ADD_NUMBER_TO_OBJECT FAILED!"); \
		return 500; \
	} \
}

#define JSON_ADD_NULL_TO_OBJECT(object, key) {\
	cJSON *null_item = cJSON_CreateNull(); \
	if(null_item == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_internal_error(api); \
		log_err("JSON_ADD_NULL_TO_OBJECT FAILED!"); \
		return 500; \
	} \
	cJSON_AddItemToObject(object, key, null_item); \
}

#define JSON_ADD_BOOL_TO_OBJECT(object, key, val) {\
	const cJSON_bool value = val; \
	cJSON *bool_item = cJSON_CreateBool(value); \
	if(bool_item == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_internal_error(api); \
		log_err("JSON_ADD_BOOL_TO_OBJECT FAILED!"); \
		return 500; \
	} \
	cJSON_AddItemToObject(object, key, bool_item); \
}

#define JSON_ADD_NUMBER_TO_ARRAY(object, num){ \
	const double number = num; \
	cJSON *number_item = cJSON_CreateNumber(number); \
	cJSON_AddItemToArray(object, number_item); \
}

#define JSON_REPLACE_NUMBER_IN_ARRAY(object, index, num){ \
	const double number = num; \
	cJSON *number_item = cJSON_CreateNumber(number); \
	cJSON_ReplaceItemInArray(object, index, number_item); \
}

#define JSON_ADD_BOOL_TO_ARRAY(object, val){ \
	const cJSON_bool value = val; \
	cJSON *bool_item = cJSON_CreateBool(value); \
	cJSON_AddItemToArray(object, bool_item); \
}

#define JSON_REF_STR_IN_ARRAY(array, string){ \
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
}

#define JSON_COPY_STR_TO_ARRAY(array, string){ \
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
}

// cJSON_AddItemToObject() does not return anything
// Note that this operation transfers the ownership of the added item to the
// new parent so that when that array or object is deleted, it gets deleted as well.
#define JSON_ADD_ITEM_TO_OBJECT(object, key, item) cJSON_AddItemToObject(object, key, item)

#define JSON_DELETE(object) cJSON_Delete(object)

#define JSON_SEND_OBJECT(object){ \
	const char* msg = json_formatter(object); \
	if(msg == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_internal_error(api); \
		log_err("JSON_SEND_OBJECT FAILED!"); \
		return 500; \
	} \
	send_http(api, "application/json; charset=utf-8", msg); \
	cJSON_Delete(object); \
	return 200; \
}

#define JSON_SEND_OBJECT_UNLOCK(object){ \
	const char* msg = json_formatter(object); \
	if(msg == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_internal_error(api); \
		log_err("JSON_SEND_OBJECT FAILED!"); \
		unlock_shm(); \
		return 500; \
	} \
	send_http(api, "application/json; charset=utf-8", msg); \
	cJSON_Delete(object); \
	unlock_shm(); \
	return 200; \
}

#define JSON_SEND_OBJECT_CODE(object, code){ \
	const char* msg = json_formatter(object); \
	if(msg == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_internal_error(api); \
		log_err("JSON_SEND_OBJECT_CODE FAILED!"); \
		return 500; \
	} \
	send_http_code(api, "application/json; charset=utf-8", code, msg); \
	cJSON_Delete(object); \
	return code; \
}
/*
#define JSON_SEND_OBJECT_AND_HEADERS(object, additional_headers){ \
	const char* msg = json_formatter(object); \
	if(msg == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_internal_error(api); \
		log_err("JSON_SEND_OBJECT_AND_HEADERS FAILED!"); \
		return 500; \
	} \
	send_http(api, "application/json; charset=utf-8", additional_headers, msg); \
	cJSON_Delete(object); \
	free(additional_headers); \
	return 200; \
}

#define JSON_SEND_OBJECT_AND_HEADERS_CODE(object, code, additional_headers){ \
	const char* msg = json_formatter(object); \
	if(msg == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_internal_error(api); \
		log_err("JSON_SEND_OBJECT_AND_HEADERS_CODE FAILED!"); \
		return 500; \
	} \
	send_http_code(api, "application/json; charset=utf-8", additional_headers, code, msg); \
	cJSON_Delete(object); \
	free(additional_headers); \
	return code; \
}
*/