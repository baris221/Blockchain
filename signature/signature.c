#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../rsa/rsaH.h"
#include "../primal/primalH.h"
#include "../key/keyH.h"
#include "../signature/signatureH.h"



Signature* init_signature(long* content, int size)
{
	Signature* newSignature = (Signature*) malloc(sizeof(Signature));
	if (!newSignature)
	{
		printf("[Init_Signature Function] Erreur Malloc\n");
		return NULL;
	}

	newSignature->size = size;

	newSignature->content = content;

	return newSignature;
}

Signature* sign(char* mess, Key* sKey)
{
	if (!mess)
	{
		printf("[sign Function] Erreur mess is NULL\n");
		return NULL;
	}

	if (!sKey)
	{
		printf("[sign Function] Erreur sKey is NULL\n");
		return NULL;
	}

	int size = strlen(mess);
	long* crypted = encrypt(mess, sKey->val, sKey->n);

	Signature* mySign = init_signature(crypted, size);

	return mySign;
}


char* signature_to_str(Signature* sgn)
{
	char* result = malloc(10 * sgn->size * sizeof(char));
 	result[0]= '#';
 	int pos = 1;
 	char buffer[156];

 	for(int i = 0; i < sgn->size; i++) {
 		sprintf(buffer, "%lx", sgn->content[i]);
 		for(int j = 0; j < strlen(buffer); j++) {
 			result[pos] = buffer[j];
 			pos = pos +1;
 		}
		result[pos] = '#';
 		pos = pos + 1;
 	}
	result[pos] = '\0';
 	result = realloc(result, (pos + 1) * sizeof(char));
 	return result;
 }

Signature* str_to_signature(char* str)
{
 	int len = strlen(str);
 	long* content = (long *) malloc(sizeof(long) * len);
 	int num = 0;
 	char buffer[256];
 	int pos = 0;

 	for (int i = 0; i < len; i++) {
 		if (str[i] != '#') {
 			buffer[pos] = str[i];
 			pos = pos +1;
 		} else {
 			if (pos != 0) {
 				buffer[pos] = '\0';
 				sscanf(buffer, "%lx", &(content[num]));
 				num = num + 1;
 				pos = 0;
 			}
 		}
 	}

 	content = realloc(content, num * sizeof(long));
 	return init_signature(content, num);
}

void delete_signature(Signature* sgn)
{
	if (!sgn)
	{
		printf("[delete_signature Function] Erreur sgn is NULL\n");
		return;
	}

	free(sgn->content);
	free(sgn);
	return;
}