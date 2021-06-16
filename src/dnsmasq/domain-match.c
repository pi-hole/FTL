/* dnsmasq is Copyright (c) 2000-2021 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
     
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "dnsmasq.h"

static int order(char *qdomain, int leading_dot, size_t qlen, struct server *serv);
static int order_qsort(const void *a, const void *b);
static int order_servers(struct server *s, struct server *s2);

void build_server_array(void)
{
  struct server *serv;
  int count = 0;
  
  for (serv = daemon->servers; serv; serv = serv->next)
    count++;

  for (serv = daemon->local_domains; serv; serv = serv->next)
    count++;
  
  if (count > daemon->serverarraysz)
    {
      struct server **new;

      if ((new = whine_malloc(count * sizeof(struct server *))))
	{
	  if (daemon->serverarray)
	    free(daemon->serverarray);
	  
	  daemon->serverarray = new;
	  daemon->serverarraysz = count;
	}
    }

  count = 0;
  
  for (serv = daemon->servers; serv; serv = serv->next, count++)
    {
      daemon->serverarray[count] = serv;
      serv->serial = count;
      serv->last_server = -1;
    }

  for (serv = daemon->local_domains; serv; serv = serv->next, count++)
    daemon->serverarray[count] = serv;
  
  qsort(daemon->serverarray, daemon->serverarraysz, sizeof(struct server *), order_qsort);

  /* servers need the location in the array to find all the whole
     set of equivalent servers from a pointer to a single one. */
  for (count = 0; count < daemon->serverarraysz; count++)
    if (!(daemon->serverarray[count]->flags & (SERV_LITERAL_ADDRESS | SERV_USE_RESOLV)))
      daemon->serverarray[count]->arrayposn = count;
}

/* we're looking for the server whose domain is the longest exact match
   to the RH end of qdomain, or a local address if the flags match.
   Add '.' to the LHS of the query string so
   server=/.example.com/ works.

   A flag of F_SERVER returns an upstream server only.
   A flag of F_DNSSECOK returns a DNSSEC capable server only and
   also disables NODOTS servers from consideration.
   A flag of F_DOMAINSRV returns a domain-specific server only.
   return 0 if nothing found, 1 otherwise.
*/
int lookup_domain(char *qdomain, int flags, int *lowout, int *highout)
{
  int rc, nodots, leading_dot = 1;
  ssize_t qlen, maxlen;
  int try, high, low = 0;
  int nlow = 0, nhigh = 0;
  char *cp;

  /* may be no configured servers. */
  if (daemon->serverarraysz == 0)
    return 0;
  
  maxlen = strlen(daemon->serverarray[0]->domain);
  
  /* find query length and presence of '.' */
  for (cp = qdomain, nodots = 1, qlen = 0; *cp; qlen++, cp++)
    if (*cp == '.')
      nodots = 0;

  /* Handle empty name, and searches for DNSSEC queries without
     diverting to NODOTS servers. */
  if (qlen == 0 || flags & F_DNSSECOK)
    nodots = 0;

  /* No point trying to match more than the largest server domain */
  if (qlen > maxlen)
    {
      qdomain += qlen - maxlen;
      qlen = maxlen;
      leading_dot = 0;
    }
  
  /* Search shorter and shorter RHS substrings for a match */
  while (qlen >= 0)
    {
      /* Note that when we chop off a character, all the possible matches
	 MUST be at a larger index than the nearest failing match with one more
	 character, since the array is sorted longest to smallest. Hence 
	 we don't reset low here. */
      high = daemon->serverarraysz;
      
      /* binary search */
      do 
	{
	  try = (low + high)/2;
	  
	  if ((rc = order(qdomain, leading_dot, qlen, daemon->serverarray[try])) == 0)
	    break;
	  
	  if (rc <  0)
	    {
	      if (high == try)
		break;
	      high = try;
	    }
	  else
	    {
	      if (low == try)
		break;
	      low = try;
	    }
	}
      while (low != high);
      
      if (rc == 0)
	{
	  /* We've matched a setting which says to use servers without a domain.
	     Continue the search with empty query (the last character gets stripped
	     by the loop. */
	  if (daemon->serverarray[try]->flags & SERV_USE_RESOLV)
	    {
	      qdomain += qlen - 1;
	      qlen = 1;
	    }
	  else
	    {
	      /* We have a match, but it may only be (say) an IPv6 address, and
		 if the query wasn't for an AAAA record, it's no good, and we need
		 to continue generalising */
	      if (filter_servers(try, flags, &nlow, &nhigh))
		break;
	    }
	}

      if (leading_dot)
	leading_dot = 0;
      else
	{
	  qlen--;
	  qdomain++;
	}
    }
  
  /* domain has no dots, and we have at least one server configured to handle such,
     These servers always sort to the very end of the array. 
     A configured server eg server=/lan/ will take precdence. */
  if (nodots &&
      (daemon->serverarray[daemon->serverarraysz-1]->flags & SERV_FOR_NODOTS) &&
      (nlow == nhigh || strlen(daemon->serverarray[nlow]->domain) == 0))
    filter_servers(daemon->serverarraysz-1, flags, &nlow, &nhigh);
  
  /* F_DOMAINSRV returns only domain-specific servers, so if we got to a 
     general server, return empty set. */
  if (nlow != nhigh && (flags & F_DOMAINSRV) && strlen(daemon->serverarray[nlow]->domain) == 0)
    nlow = nhigh;
  
  if (lowout)
    *lowout = nlow;
  
  if (highout)
    *highout = nhigh;

  if (nlow == nhigh)
    return 0;

  return 1;
}

/* Return first server in group of equivalent servers; this is the "master" record. */
int server_samegroup(struct server *a, struct server *b)
{
  return order_servers(a, b) == 0;
}

int filter_servers(int seed, int flags, int *lowout, int *highout)
{
  int nlow = seed, nhigh = seed;
  int i;
  
  /* expand nlow and nhigh to cover all the records with the same domain 
     nlow is the first, nhigh - 1 is the last. nlow=nhigh means no servers,
     which can happen below. */
  while (nlow > 0 && order_servers(daemon->serverarray[nlow-1], daemon->serverarray[nlow]) == 0)
    nlow--;
  
  while (nhigh < daemon->serverarraysz-1 && order_servers(daemon->serverarray[nhigh], daemon->serverarray[nhigh+1]) == 0)
	nhigh++;
  
  nhigh++;
  
  /* Now the servers are on order between low and high, in the order
     return zero for both, IPv6 addr, IPv4 addr, no-data return, send upstream.
     
     See which of those match our query in that priority order and narrow (low, high) */

  for (i = nlow; i < nhigh && (daemon->serverarray[i]->flags & SERV_6ADDR); i++);

  if (i != nlow && (flags & F_IPV6))
    nhigh = i;
  else
    {
       nlow = i;

       for (i = nlow; i < nhigh && (daemon->serverarray[i]->flags & SERV_4ADDR); i++);
      
      if (i != nlow && (flags & F_IPV4))
	nhigh = i;
      else
	{
	  nlow = i;
	  
	  for (i = nlow; i < nhigh && (daemon->serverarray[i]->flags & SERV_ALL_ZEROS); i++);
	  
	  if (i != nlow && (flags & (F_IPV4 | F_IPV6)))
	    nhigh = i;
	  else
	    {
	      nlow = i;
	      
	      for (i = nlow; i < nhigh && (daemon->serverarray[i]->flags & SERV_LITERAL_ADDRESS); i++);
	      
	      /* --local=/domain/, only return if we don't need a server. */
	      if (i != nlow && !(flags & (F_DNSSECOK | F_DOMAINSRV | F_SERVER)))
		nhigh = i;
	      else
		{
		  nlow = i;
		  /* If we want a server that can do DNSSEC, and this one can't, 
		     return nothing. */
		  if ((flags & F_DNSSECOK) && !(daemon->serverarray[nlow]->flags & SERV_DO_DNSSEC))
		    nlow = nhigh;
		}
	    }
	}
    }

  *lowout = nlow;
  *highout = nhigh;
  
  return (nlow != nhigh);
}

int is_local_answer(time_t now, int first, char *name)
{
  int flags = 0;
  int rc = 0;
    
  if ((flags = daemon->serverarray[first]->flags) & SERV_LITERAL_ADDRESS)
    {
      if (flags & SERV_4ADDR)
	rc = F_IPV4;
      else if (flags & SERV_6ADDR)
	rc = F_IPV6;
      else if (flags & SERV_ALL_ZEROS)
	rc = F_IPV4 | F_IPV6;
      else
	rc = check_for_local_domain(name, now) ? F_NOERR : F_NXDOMAIN;
    }

  return rc;
}

size_t make_local_answer(int flags, int gotname, size_t size, struct dns_header *header, char *name, int first, int last)
{
  int trunc = 0;
  unsigned char *p;
  int start;
  union all_addr addr;
  
  if (flags & (F_NXDOMAIN | F_NOERR))
    log_query(flags | gotname | F_NEG | F_CONFIG | F_FORWARD, name, NULL, NULL);
	  
  setup_reply(header, flags);
	  
  if (!(p = skip_questions(header, size)))
    return 0;
	  
  if (flags & gotname & F_IPV4)
    for (start = first; start != last; start++)
      {
	struct serv_addr4 *srv = (struct serv_addr4 *)daemon->serverarray[start];

	if (srv->flags & SERV_ALL_ZEROS)
	  memset(&addr, 0, sizeof(addr));
	else
	  addr.addr4 = srv->addr;
	
	header->ancount = htons(ntohs(header->ancount) + 1);
	add_resource_record(header, ((char *)header) + 65536, &trunc, sizeof(struct dns_header), &p, daemon->local_ttl, NULL, T_A, C_IN, "4", &addr);
	log_query((flags | F_CONFIG | F_FORWARD) & ~F_IPV6, name, (union all_addr *)&addr, NULL);
      }
  
  if (flags & gotname & F_IPV6)
    for (start = first; start != last; start++)
      {
	struct serv_addr6 *srv = (struct serv_addr6 *)daemon->serverarray[start];

	if (srv->flags & SERV_ALL_ZEROS)
	  memset(&addr, 0, sizeof(addr));
	else
	  addr.addr6 = srv->addr;
	
	header->ancount = htons(ntohs(header->ancount) + 1);
	add_resource_record(header, ((char *)header) + 65536, &trunc, sizeof(struct dns_header), &p, daemon->local_ttl, NULL, T_AAAA, C_IN, "6", &addr);
	log_query((flags | F_CONFIG | F_FORWARD) & ~F_IPV4, name, (union all_addr *)&addr, NULL);
      }

  if (trunc)
    header->hb3 |= HB3_TC;

  return p - (unsigned char *)header;
}

#ifdef HAVE_DNSSEC
int dnssec_server(struct server *server, char *keyname, int *firstp, int *lastp)
{
  int first, last, index;

  /* Find server to send DNSSEC query to. This will normally be the 
     same as for the original query, but may be another if
     servers for domains are involved. */		      
  if (!lookup_domain(keyname, F_DNSSECOK, &first, &last))
    return -1;

  for (index = first; index != last; index++)
    if (daemon->serverarray[index] == server)
      break;
	      
  /* No match to server used for original query.
     Use newly looked up set. */
  if (index == last)
    index =  daemon->serverarray[first]->last_server == -1 ?
      first : daemon->serverarray[first]->last_server;

  if (firstp)
    *firstp = first;

  if (lastp)
    *lastp = last;
   
  return index;
}
#endif

/* order by size, then by dictionary order */
static int order(char *qdomain, int leading_dot, size_t qlen, struct server *serv)
{
  size_t dlen = 0;
  int rc;
  
  /* servers for dotless names always sort last 
     searched for name is never dotless. */
  if (serv->flags & SERV_FOR_NODOTS)
    return -1;

  if (leading_dot)
    qlen++;
  
  dlen = strlen(serv->domain);
  
  if (qlen < dlen)
    return 1;
  
  if (qlen > dlen)
    return -1;

  if (leading_dot && (rc = '.' - serv->domain[0]) != 0)
    return rc;
     
  return strcmp(qdomain, leading_dot ? &serv->domain[1] : serv->domain);
}

static int order_servers(struct server *s1, struct server *s2)
{
   size_t dlen = strlen(s1->domain);

   /* need full comparison of dotless servers in 
      order_qsort() and filter_servers() */
   if (s1->flags & SERV_FOR_NODOTS)
     return (s2->flags & SERV_FOR_NODOTS) ? 0 : 1;
   
   return order(s1->domain, 0, dlen, s2);
}
  
static int order_qsort(const void *a, const void *b)
{
  int rc;
  
  struct server *s1 = *((struct server **)a);
  struct server *s2 = *((struct server **)b);
  
  rc = order_servers(s1, s2);

  /* Sort all literal NODATA and local IPV4 or IPV6 responses together,
     in a very specific order. */
  if (rc == 0)
    rc = (s2->flags & (SERV_LITERAL_ADDRESS | SERV_4ADDR | SERV_6ADDR | SERV_ALL_ZEROS)) -
    (s1->flags & (SERV_LITERAL_ADDRESS | SERV_4ADDR | SERV_6ADDR | SERV_ALL_ZEROS));

  /* Finally, order by appearance in /etc/resolv.conf etc, for --strict-order */
  if (rc == 0)
    if (!(s1->flags & SERV_LITERAL_ADDRESS))
      rc = s1->serial - s2->serial;

  return rc;
}
