#ifndef CUSTOM_DNS_H
#define CUSTOM_DNS_H

#include "FTL.h"
#include "datastructure.h"

bool find_custom_dns(const char *domain, const clientsData *client, char **targetIP, int *type, int *ttl);

#endif // CUSTOM_DNS_H
