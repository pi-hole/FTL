/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Query table database prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef DATABASE_QUERY_TABLE_H
#define DATABASE_QUERY_TABLE_H

int get_number_of_queries_in_DB(void);
void delete_old_queries_in_DB(void);
void save_to_DB(void);
void read_data_from_DB(void);

#endif //DATABASE_QUERY_TABLE_H
