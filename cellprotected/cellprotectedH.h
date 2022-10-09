#ifndef CELL_PROTECTED_H
#define CELL_PROTECTED_H

#include "../protected/protectedH.h"

typedef struct cellProtected {
 	Protected* data;
 	struct cellProtected* next;
} CellProtected;

CellProtected* create_cell_protected(Protected* pr);
void add_cell_protected(CellProtected** cellProtected, Protected* pr);
CellProtected* read_protected(char* filename);
void print_list_protected(CellProtected* LP);
void delete_cell_protected(CellProtected* cp);
void delete_list_protected(CellProtected* cellProtected);

void verify_list_protected(CellProtected **LCP);


//Pour du O(1) il aurait fallut avoir le dernier pointeur de c1 dans la structure CellTree de chaque node pour directement refaire le chainage et ne pas avoir a retraverser toute la liste (Liste doublement chainée)
CellProtected *fusionner_list_protected(CellProtected *votes1, CellProtected *votes2);

CellProtected *copie_list_protected(CellProtected *votes);

#endif
