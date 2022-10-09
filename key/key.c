#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../rsa/rsaH.h"
#include "../primal/primalH.h"
#include "../key/keyH.h"

void init_key(Key* key, long val, long n)
{
	if (!key)
	{
		printf("[Init_Key Function] Erreur key is NULL\n");
		return;
	}

	key->val = val;
	key->n = n;
}

void init_pair_keys(Key* pKey, Key* sKey, long low_size, long up_size)
{
	if (!pKey || !sKey)
	{
		printf("[Init_Key Function] Erreur pKey OR sKey is NULL\n");
		return;
	}

	long p = random_prime_number(low_size, up_size, 5000);
  	long q = random_prime_number(low_size, up_size, 5000);

  	while(p == q)
	{
    	q = random_prime_number(low_size, up_size, 5000);
  	}

  	long n,s,u;

  	generate_key_values(p,q,&n,&s,&u);

  	//Clés positives:
  	if (u < 0)
	{
    	long t = (p-1)*(q-1);
    	u += t;
  	}

  	//pKey = s, n;
  	//sKey = u, n;
  	init_key(pKey, s, n);
  	init_key(sKey, u, n);
}

char* key_to_str(Key* key)
{
	if (!key)
	{
		printf("[Key_To_Str Function] Erreur key is NULL\n");
		return NULL;
	}

	long value = key->val;
	long n = key->n;

	char* keyString = (char*) malloc(sizeof(char) * 256); //Buffer de 256 bytes
	if (!keyString)
	{
		printf("[Key_To_Str Function] Erreur keyString is NULL\n");
		return NULL;
	}

	sprintf(keyString, "(%lx,%lx)", value, n);

	return keyString;
}


Key* str_to_key(char* str)
{
	if (!str)
	{
		printf("[Str_To_Key Function] Erreur str is NULL\n");
		return NULL;
	}

	Key* newKey = (Key*) malloc(sizeof(Key));
	if(!newKey)
	{
		printf("[Str_To_Key Function] Erreur newKey is NULL\n");
		return NULL;
	}
	long value, n;
	sscanf(str, "(%lx,%lx)", &value, &n);

	newKey->val = value;
	newKey->n = n;

	return newKey;
}


void delete_key(Key* key)
{
	if (!key)
	{
		printf("[delete_key Function] Erreur key is NULL\n");
		return;
	}

	free(key);
	return;
}

Key *copie_key(Key *key)    
{
   Key *new = (Key *)malloc(sizeof(Key));
   new->val = key->val;
   new->n = key->n;
   return new;
}