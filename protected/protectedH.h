#ifndef PROTECTED_H
#define PROTECTED_H

#include "../key/keyH.h"
#include "../signature/signatureH.h"

typedef struct {
	Key* pKey;
	char* mess;
	Signature* sgn;
} Protected;

Protected* init_protected(Key* pKey, char* mess, Signature* sgn);
int verify(Protected* pr);
char* protected_to_str(Protected* pr);
Protected* str_to_protected(char* protected_str);
void delete_protected(Protected* pr);

int exists(char* key, char** tab_key_str, int size);

void generate_random_data(int nv, int nc);

#endif