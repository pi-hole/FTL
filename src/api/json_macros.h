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
#include "http.h"

// Provides a compile-time flag for JSON formatting
// This should never be needed as all modern browsers
// tyoically contain a JSON explorer
#ifdef JSON_FORMATTED
/* Examplary output:
{
	"queries in database":	70,
	"database filesize":	49152,
	"SQLite version":	"3.30.1"
}
*/
#define JSON_FORMATTER(object) cJSON_Print(object)
#else
/* Exemplary output
{"queries in database":70,"database filesize":49152,"SQLite version":"3.30.1"}
*/
#define JSON_FORMATTER(object) cJSON_PrintUnformatted(object)
#endif

#define JSON_NEW_OBJ() cJSON_CreateObject();
#define JSON_NEW_ARRAY() cJSON_CreateArray();

#define JSON_ARRAY_ADD_ITEM(array, item) cJSON_AddItemToArray(array, item);

#define JSON_OBJ_COPY_STR(object, key, string){ \
	cJSON *string_item = cJSON_CreateString((const char*)string); \
	if(string_item == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_error(conn); \
		return 500; \
	} \
	cJSON_AddItemToObject(object, key, string_item); \
}

#define JSON_OBJ_REF_STR(object, key, string){ \
	cJSON *string_item = cJSON_CreateStringReference((const char*)string); \
	if(string_item == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_error(conn); \
		return 500; \
	} \
	cJSON_AddItemToObject(object, key, string_item); \
}

#define JSON_OBJ_ADD_NUMBER(object, key, number){ \
	if(cJSON_AddNumberToObject(object, key, (double)number) == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_error(conn); \
		return 500; \
	} \
}

#define JSON_OBJ_ADD_NULL(object, key) {\
	cJSON *null_item = cJSON_CreateNull(); \
	if(null_item == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_error(conn); \
		return 500; \
	} \
	cJSON_AddItemToObject(object, key, null_item); \
}

#define JSON_OBJ_ADD_BOOL(object, key, value) {\
	cJSON *bool_item = cJSON_CreateBool(value); \
	if(bool_item == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_error(conn); \
		return 500; \
	} \
	cJSON_AddItemToObject(object, key, bool_item); \
}

#define JSON_ARRAY_ADD_NUMBER(object, number){ \
	cJSON *number_item = cJSON_CreateNumber((double)number); \
	cJSON_AddItemToArray(object, number_item); \
}

#define JSON_ARRAY_REF_STR(array, string){ \
	cJSON *string_item = cJSON_CreateStringReference((const char*)string); \
	if(string_item == NULL) \
	{ \
		cJSON_Delete(array); \
		send_http_error(conn); \
		return 500; \
	} \
	cJSON_AddItemToArray(array, string_item); \
}

#define JSON_ARRAY_COPY_STR(array, string){ \
	cJSON *string_item = cJSON_CreateString((const char*)string); \
	if(string_item == NULL) \
	{ \
		cJSON_Delete(array); \
		send_http_error(conn); \
		return 500; \
	} \
	cJSON_AddItemToArray(array, string_item); \
}

// cJSON_AddItemToObject() does not return anything
// Note that this operation transfers the ownership of the added item to the
// new parent so that when that array or object is deleted, it gets deleted as well.
#define JSON_OBJ_ADD_ITEM(object, key, item) cJSON_AddItemToObject(object, key, item)

#define JSON_DELETE(object) cJSON_Delete(object)

#define JSON_SENT_OBJECT(object){ \
	const char* msg = JSON_FORMATTER(object); \
	if(msg == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_error(conn); \
		return 500; \
	} \
	send_http(conn, "application/json; charset=utf-8", NULL, msg); \
	cJSON_Delete(object); \
	return 200; \
}

#define JSON_SENT_OBJECT_AND_HEADERS(object, additional_headers){ \
	const char* msg = JSON_FORMATTER(object); \
	if(msg == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_error(conn); \
		return 500; \
	} \
	send_http(conn, "application/json; charset=utf-8", additional_headers, msg); \
	cJSON_Delete(object); \
	free(additional_headers); \
	return 200; \
}

#define JSON_SENT_OBJECT_AND_HEADERS_CODE(object, code, additional_headers){ \
	const char* msg = JSON_FORMATTER(object); \
	if(msg == NULL) \
	{ \
		cJSON_Delete(object); \
		send_http_error(conn); \
		return 500; \
	} \
	send_http_unauth(conn, additional_headers, msg); \
	cJSON_Delete(object); \
	free(additional_headers); \
	return code; \
}
