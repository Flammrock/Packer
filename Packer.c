/*********************************************************************************\
* Copyright (c) 2021 - Flammrock                                                  *
*                                                                                 *
* Permission is hereby granted, free of charge, to any person obtaining a copy    *
* of this software and associated documentation files (the "Software"), to deal   *
* in the Software without restriction, including without limitation the rights    *
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell       *
* copies of the Software, and to permit persons to whom the Software is           *
* furnished to do so, subject to the following conditions:                        *
*                                                                                 *
* The above copyright notice and this permission notice shall be included in all  *
* copies or substantial portions of the Software.                                 *
*                                                                                 *
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR      *
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,        *
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE     *
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER          *
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,   *
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE   *
* SOFTWARE.                                                                       *
\*********************************************************************************/




/**********************\
*                      *
*       INCLUDE        *
*                      *
\**********************/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <assert.h>
#include <jansson.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <time.h>




/**********************\
*                      *
*        MACRO         *
*                      *
\**********************/

// pour les fonctions gz
#define CHUNK 16384

// listes des codes erreurs
#define EXIT_CODE_BAD_ALLOC_MEMORY       2
#define EXIT_CODE_BAD_NUMBER             3
#define EXIT_CODE_BAD_ARGUMENT           4
#define EXIT_CODE_IO_ERROR               5
#define EXIT_CODE_ERROR_JSON             6
#define EXIT_CODE_ALREADY_PACK           7
#define EXIT_CODE_ERROR_BUILD_BUFFER     8
#define EXIT_CODE_ERROR_SIGNATURE_CALC   9
#define EXIT_CODE_IO_FILE                10

// listes des commandes
#define CMD_UNPACK    0
#define CMD_PACK      1
#define CMD_BUILDTRB  2
#define CMD_SIG       3
#define CMD_GZIP      4
#define CMD_UNGZIP    5




/**********************\
*                      *
*     PROTOTYPE        *
*                      *
\**********************/

// permet de convertir une chaine de caractères en nombre
void str2long(long *out, char *s, int base, int isint);

// wrapper de quelques fonctions pour les rendre safe
void*   safe_malloc(size_t n);
void*   safe_calloc(size_t n_items, size_t item_size);
void*   safe_realloc(void *ptr, size_t size);
FILE*   safe_fopen(const char *filename, const char *accessMode, int throw_error);
json_t* safe_json_loadb(uint8_t* buffer, size_t size, size_t flag);

// permet d'afficher des buffers
void print_hex_view(char *buffer, int size);

// permet de remplacer la valeur d'une clé recursivement dans un objet JSON
void json_replace(json_t* o, char* k, json_t* r);

// opérations usuelles pour des fichiers .gz
int      gzcheck(unsigned char *filename);
int      gzprintfile(unsigned char *filename);
uint8_t* gzloadfile(unsigned char *filename, size_t* buffersize, int check);
int      gzcompressdata(FILE *dest, unsigned char* source, size_t len, gz_header* header, int level);
int      gzwritefile(unsigned char *filename, uint8_t *buffer, size_t buffersize, int level);
int      gzwritestream(FILE *stream, uint8_t *buffer, size_t buffersize, int level);

// opérations sur les fichiers scb et nsb
uint8_t* packer_get_signature(uint8_t *buffer, size_t size, size_t *sigsize);
uint8_t* packer_get_jsonstring(uint8_t *buffer, size_t size, size_t *jsonsize);
uint8_t* packer_get_data(char *filename, size_t* sizesig, size_t* sizejson, int verbose, int prettify, int crlf);

// permet de calculer des signatures
int hmacsha1(char *hexdigest, uint8_t* key, const uint8_t *data, size_t databytes);
int sha1digest(uint8_t *digest, char *hexdigest, const uint8_t *data, size_t databytes);

// permet de convertir des sauts de lignes LF (Unix, Android, ...) en saut de lignes CRLF (Windows)
char* convert_line_feed(char *buffer, size_t size, size_t *new_size, int crlf, int verbose);

// copyright + aide
void copyright();
void help();

// liste des arguments qui peuvent être récupérés
typedef struct {
	int command;
	int verbose;
	char* input;
	char* output;
	int prettify;
	int minify;
	int stdoutconsole;
	int level;
	long int timestamp;
	char* nsb;
	char* scb;
	int crlf;
	char* folder;
} arguments;

// fonctions qui permet de récupérer les argumenrs et renvoie une structure arguments
arguments* get_arguments(int argc, char **argv);

// si un argument est mauvais, on appelle cette fonction
void bad_arguments(char*k,int m);

// permet de throw une erreur IO
void bad_io_error(char *filename);




/**********************\
*                      *
*        MAIN          *
*                      *
\**********************/

///[ENTRY POINT]
int main(int argc, char **argv) {
	
	// s'il n'y a pas d'arguments, on affiche le copyright ainsi que l'aide
	if (argc<=1) {
		copyright();
		help();
		return 0;
	}
	
	// on parse les arguments
	arguments* args = get_arguments(argc,argv);
	
	// si on souhaite unpack
	if (args->command==CMD_UNPACK) {
		
		// l'input est nécessaire
		if (args->input == NULL) {
			bad_arguments("-i, --input",4);
		}
		
		// on recupère les données du fichier mis en input
		size_t sizejson = 0;
		size_t sizesig = 0;
		uint8_t* buffer = packer_get_data(args->input, &sizesig, &sizejson, args->verbose, args->prettify, args->crlf);
		
		// si un fichier d'output est spécifié, alors on écrit le résultat dedans
		if (args->output!=NULL) {
			
			if (args->verbose) fprintf(stderr,"[debug] Ecriture dans le fichier \"%s\"...",args->output);
			
			// on ouvre le fichier
			FILE* file = fopen(args->output,"wb");
			if (file==NULL) {
				fprintf(stderr,"\nErreur: impossible d'ouvrir le fichier \"%s\".\n",args->output);
				exit(EXIT_CODE_IO_ERROR);
			}
			
			// on écrit les données unpack
			if (fwrite(buffer+sizesig+1,sizeof(uint8_t),sizejson,file)!=sizejson) {
				if (args->verbose) fprintf(stderr,"\n");
				bad_io_error(args->output);
			}
			
			// onferme le fichier
			fclose(file);
			
			if (args->verbose) fprintf(stderr," OK\n");
		}
		
		// si --stdout est spécifié
		if (args->stdoutconsole) {
			if (args->verbose) fprintf(stderr,"[debug] Ecriture du JSON sur la console (stdout)...");
			
			// on écrit sur la console les données unpack
			if (fwrite(buffer+sizesig+1,sizeof(uint8_t),sizejson,stdout)!=sizejson) {
				if (args->verbose) fprintf(stderr,"\n");
				bad_io_error(args->output);
			}
			
			if (args->verbose) fprintf(stderr," OK\n");
		}
		
		// on libère la mémoire
		free(buffer);
		
		
		
	// si on souhaite pack
	} else if (args->command==CMD_PACK) {
		
		// l'input est nécessaire
		if (args->input == NULL) {
			bad_arguments("-i, --input",4);
		}
		
		// on récupère les données du fichier mis en input
		size_t sizejson = 0;
		size_t sizesig = 0;
		uint8_t* buffer = packer_get_data(args->input, &sizesig, &sizejson, args->verbose, args->prettify, args->crlf);
		
		// si un fichier d'output est spécifié, alors on écrit le résultat dedans
		if (args->output!=NULL) {
			if (args->verbose) fprintf(stderr,"[debug] Ecriture dans le fichier \"%s\"...",args->output);
			
			// on écrit les données pack
			if (gzwritefile(args->output, buffer, sizejson+sizesig+1, args->level)!=0) {
				if (args->verbose) fprintf(stderr,"\n");
				bad_io_error(args->output);
			}
			
			if (args->verbose) fprintf(stderr," OK\n");
		}
		
		// si --stdout est spécifié
		if (args->stdoutconsole) {
			if (args->verbose) fprintf(stderr,"[debug] Ecriture du fichier pack sur la console (stdout)...");
			
			// on écrit sur la console les données pack
			if (gzwritestream(stdout, buffer, sizejson+sizesig+1, args->level)!=0) {
				if (args->verbose) fprintf(stderr,"\n");
				bad_io_error(args->output);
			}
			
			if (args->verbose) fprintf(stderr," OK\n");
		}
		
		// on libère la mémoire
		free(buffer);
		
	// si on souhaite construire le fichier trb
	} else if (args->command==CMD_BUILDTRB) {
		
		// le fichier nsb est nécessaire
		if (args->nsb == NULL) {
			bad_arguments("--nsb",4);
		}
		
		// le fichier scb est nécessaire
		if (args->scb == NULL) {
			bad_arguments("--scb",4);
		}
		
		// le dossier est nécessaire
		if (args->folder == NULL) {
			bad_arguments("--folder",4);
		}
		
		// on calcul juste la longueur de la chaine de caractères args->folder
		size_t folderlen = strlen(args->folder);
		
		// on récupère les données de nsb et scb
		size_t scb_sizejson = 0;
		size_t scb_sizesig = 0;
		uint8_t* scb_buffer = packer_get_data(args->scb, &scb_sizesig, &scb_sizejson, args->verbose, args->prettify, 0);
		size_t nsb_sizejson = 0;
		size_t nsb_sizesig = 0;
		uint8_t* nsb_buffer = packer_get_data(args->nsb, &nsb_sizesig, &nsb_sizejson, args->verbose, args->prettify, 0);
		
		// on parse les données
		json_t *scb_root = safe_json_loadb(scb_buffer+scb_sizesig+1, scb_sizejson, 0);
		json_t *nsb_root = safe_json_loadb(nsb_buffer+nsb_sizesig+1, nsb_sizejson, 0);
		
		// on vérifie que les données sont valides
		if (json_is_object(scb_root)==0) {
			fprintf(stderr,"Erreur: scb n'est pas un objet JSON.\n");
			exit(EXIT_CODE_ERROR_JSON);
		}
		if (json_is_object(nsb_root)==0) {
			fprintf(stderr,"Erreur: nsb n'est pas un objet JSON.\n");
			exit(EXIT_CODE_ERROR_JSON);
		}
		
		// on essai de trouver la clé "CarsSecureData" dans scb
		if (args->verbose) fprintf(stderr,"[debug] Detection clef \"CarsSecureData\" (fichier scb)...");
		json_t* CarsSecureData = json_object_get(scb_root, "CarsSecureData");
		if (CarsSecureData==NULL) {
			fprintf(stderr,"\nErreur: la clef \"CarsSecureData\" introuvable dans le fichier scb.\n");
			exit(EXIT_CODE_ERROR_JSON);
		}
		if (args->verbose) fprintf(stderr," OK\n");
		
		// on essai de trouver la clé "caow" dans nsb
		if (args->verbose) fprintf(stderr,"[debug] Detection clef \"caow\" (fichier nsb)...");
		json_t* caow = json_object_get(nsb_root, "caow");
		if (caow==NULL) {
			fprintf(stderr,"Erreur: la clef \"caow\" introuvable dans le fichier nsb.\n");
			exit(EXIT_CODE_ERROR_JSON);
		}
		if (args->verbose) fprintf(stderr," OK\n");
		
		// on vérifie le type des clés "caow" et "CarsSecureData"
		if (args->verbose) fprintf(stderr,"[debug] Verification des types...");
		if (json_is_object(CarsSecureData)==0) {
			fprintf(stderr,"\nErreur: la clef \"CarsSecureData\" dans le fichier scb n'est pas un objet.\n");
			exit(EXIT_CODE_ERROR_JSON);
		}
		if (json_is_array(caow)==0) {
			fprintf(stderr,"\nErreur: la clef \"caow\" dans le fichier nsb n'est pas un tableau.\n");
			exit(EXIT_CODE_ERROR_JSON);
		}
		if (args->verbose) fprintf(stderr," OK\n");
		
		// on récupère le timestamp
		if (args->verbose) fprintf(stderr,"[debug] Recuperation du timestamp\n");
		unsigned long timestamp = (unsigned long)time(NULL);
		
		// on récupère uniquement ce qui nous intéresse dans scb
		if (args->verbose) fprintf(stderr,"[debug] Recuperation des informations de scb...");
		const char *key;
		json_t *value;
		size_t _size = 2;
		size_t _index = 0;
		size_t* levels = safe_malloc((_size+1)*sizeof(size_t));
		size_t* carUIDs = safe_malloc((_size+1)*sizeof(size_t));
		json_object_foreach(CarsSecureData, key, value) {
			if (json_is_object(value)==0) {
				fprintf(stderr,"\nErreur: les valeurs de la clef \"CarsSecureData\" dans le fichier scb ne sont pas des objets.\n");
				exit(EXIT_CODE_ERROR_JSON);
			}
			json_t* cui = json_object_get(value, "cui");
			if (cui==NULL) {
				fprintf(stderr,"\nErreur: la clef \"cui\" introuvable dans le fichier scb.\n");
				exit(EXIT_CODE_ERROR_JSON);
			}
			json_t* amml = json_object_get(value, "amml");
			if (amml==NULL) {
				fprintf(stderr,"\nErreur: la clef \"amml\" introuvable dans le fichier scb.\n");
				exit(EXIT_CODE_ERROR_JSON);
			}
			if (json_is_number(cui)==0 || json_is_number(amml)==0) {
				fprintf(stderr,"\nErreur: les valeurs des clefs \"cui\" et \"amml\" ne sont pas des nombres dans le fichier scb.\n");
				exit(EXIT_CODE_ERROR_JSON);
			}
			levels[_index] = (size_t)round(json_number_value(amml));
			carUIDs[_index] = (size_t)round(json_number_value(cui));
			_index++;
			if (_index > _size-1) {
				_size*=2;
				levels = safe_realloc(levels,(_size+1)*sizeof(size_t));
				carUIDs = safe_realloc(carUIDs,(_size+1)*sizeof(size_t));
			}
		}
		if (args->verbose) fprintf(stderr," OK\n");
		
		// on récupère uniquement ce qui nous intéresse dans nsb
		if (args->verbose) fprintf(stderr,"[debug] Recuperation des informations de nsb...");
		size_t index2;
		json_t *value2;
		size_t _size2 = 2;
		size_t _index2 = 0;
		size_t* carUIDs2 = safe_malloc((_size2+1)*sizeof(size_t));
		char** crdbs = safe_malloc((_size2+1)*sizeof(char*));
		json_array_foreach(caow, index2, value2) {
			if (json_is_object(value2)!=0) {
				json_t* unid = json_object_get(value2, "unid");
				json_t* crdb = json_object_get(value2, "crdb");
				if (unid!=NULL && crdb!=NULL) {
					if (json_is_number(unid)==0 || json_is_string(crdb)==0) {
						fprintf(stderr,"\nErreur: les valeurs des clefs \"unid\" et \"crdb\" ne sont pas correctes dans le fichier nsb.\n");
						exit(EXIT_CODE_ERROR_JSON);
					}
					carUIDs2[_index2] = (size_t)round(json_number_value(unid));
					crdbs[_index2] = safe_malloc((json_string_length(crdb)+1)*sizeof(char));
					strcpy(crdbs[_index2],json_string_value(crdb));
					_index2++;
					if (_index2 > _size2-1) {
						_size2*=2;
						carUIDs2 = safe_realloc(carUIDs2,(_size2+1)*sizeof(size_t));
						crdbs = safe_realloc(crdbs,(_size2+1)*sizeof(char*));
					}
				}
			}
		}
		if (args->verbose) fprintf(stderr," OK\n");
	
		// on commence la construction du fichier trb
		if (args->verbose) fprintf(stderr,"[debug] Debut creation fichier trb\n");
		
		// on ouvre le fichier trb
		FILE* trb = NULL;
		if (args->output!=NULL) {
			trb = safe_fopen(args->output,"wb",1);
		}
		
		// on fusionne les données de scb et nsb
		char *finalbuf = safe_malloc(25*sizeof(char));
		strcpy(finalbuf,"{\"transactions\":");
		size_t finalbufsize = 25;
		size_t finalpos = 16;
		size_t indexcount = 0;
		for (size_t i = 0; i < _index2; i++) {
			for (size_t j = 0; j < _index; j++) {
				
				// si les id match
				if (carUIDs2[i]==carUIDs[j]) {
					
					if (args->verbose) fprintf(stderr,"[debug] %d:%s:%d\n",carUIDs[j],crdbs[i],levels[j]);
					
					// on converti le nombre level en chaine de caractères
					char level[100];
					size_t r = sprintf(level,"%d",levels[j]);
					
					// on construit le chemin du fichier
					char *path = safe_malloc((folderlen+1+strlen(crdbs[i])+1+r+8+1)*sizeof(char));
					path[0] = '\0';
					strcat(path,args->folder);
					strcat(path,"\\");
					strcat(path,crdbs[i]);
					strcat(path,"\\");
					strcat(path,level);
					strcat(path,"Cmlv.txt");
					if (args->verbose) fprintf(stderr,"[debug] \tChemin : %s\n",path);
					
					// on essai d'ouvrir le fichier
					if (args->verbose) fprintf(stderr,"[debug] \tOuverture du fichier \"%s\"\n",path);
					FILE* trb_part = safe_fopen(path,"rb",0);
					if (trb_part!=NULL) {
						
						// le fichier existe et on a assez de droits
						
						if (args->verbose) fprintf(stderr,"[debug] \tLecture du fichier par chunk\n");
						
						// on lit tout le fichier
						size_t sizebuf=CHUNK;
						char* buffertrb = safe_malloc((sizebuf+2)*sizeof(char));
						buffertrb[0]='[';
						size_t pos = 1;
						while (1) {
							size_t r = fread(buffertrb+pos,sizeof(char),CHUNK,trb_part);
							pos += r;
							if (pos+CHUNK > sizebuf-1) {
								sizebuf*=2;
								buffertrb = safe_realloc(buffertrb,(sizebuf+2)*sizeof(char));
							}
							if (ferror(trb_part)) {
								bad_io_error(path);
							}
							if (feof(trb_part)) {
								break;
							}
						}
						
						// on ferme le fichier (on n'en n'a plus besoins)
						fclose(trb_part);
						if (args->verbose) fprintf(stderr,"[debug] \tFermeture du fichier\n");
						
						// on corrige la fin du fichier
						if (args->verbose) fprintf(stderr,"[debug] \tCorrection du JSON\n");
						while(buffertrb[pos-1]=='\0'||isspace(buffertrb[pos-1])||buffertrb[pos-1]==',') {
							pos--;
						}
						buffertrb[pos]=']';
						buffertrb[pos+1]='\0';
						pos++;
						
						
						// on parse le JSON
						if (args->verbose) fprintf(stderr,"[debug] \tParsage du JSON\n");
						json_t *trb_root = safe_json_loadb(buffertrb, pos, JSON_COMPACT);
						
						// on remplace la clé "CarUID" par l'id
						if (args->verbose) fprintf(stderr,"[debug] \tRemplacement de la valeur de la clef \"CarUID\" par : %d\n",carUIDs[j]);
						json_replace(trb_root, "CarUID", json_integer(carUIDs[j]));
						
						// on remplace la clé "CarUID" par le timestamp
						if (args->verbose) fprintf(stderr,"[debug] \tRemplacement de la valeur de la clef \"timestamp\" par : %lu\n",timestamp);
						json_replace(trb_root, "timestamp", json_integer(timestamp));
						
						// on stringify et on compresse les données et on l'ajoute au buffer final
						size_t jsize2 = json_dumpb(trb_root, NULL, 0, JSON_COMPACT);
						if (jsize2 == 0) {
							fprintf(stderr,"\nErreur: une erreur est survenue lors de la creation du buffer.\n");
							exit(EXIT_CODE_ERROR_BUILD_BUFFER);
						}
						finalbufsize+=jsize2+3;
						finalbuf = safe_realloc(finalbuf,(finalbufsize+5)*sizeof(char));
						jsize2 = json_dumpb(trb_root, finalbuf+finalpos, jsize2, JSON_COMPACT);
						if (indexcount>0)finalbuf[finalpos] = ',';
						if (jsize2 == 0) {
							fprintf(stderr,"\nErreur: une erreur est survenue lors de la creation du buffer.\n");
							exit(EXIT_CODE_ERROR_BUILD_BUFFER);
						}
						finalpos+=jsize2-1;
						
						// on libère la mémoire
						if (args->verbose) fprintf(stderr,"[debug] \tRelease de la memoire\n");
						free(buffertrb);
						json_decref(trb_root);
						
						// on incrémente le nombre de fichier traité
						indexcount++;
						
					// sinon le fichier n'existe pas
					} else {
						if (args->verbose) fprintf(stderr,"[debug] \tIntrouvable ou droits insuffisants\n",path);
					}
				}
			}
		}
		
		// on termine le buffer correctement
		if (args->verbose) fprintf(stderr,"[debug] Fermeture buffer\n");
		finalbuf[finalpos+1] = '}';
		finalbuf[finalpos+2] = '\0';
		finalpos+=2;
		
		// on reformate le buffer
		if (args->verbose) fprintf(stderr,"[debug] Formatage JSON du buffer\n");
		json_t* trb_root_final = safe_json_loadb(finalbuf, finalpos, JSON_COMPACT);
		size_t jsize3 = json_dumpb(trb_root_final, NULL, 0, args->prettify?JSON_INDENT(4):JSON_COMPACT);
		if (jsize3 == 0) {
			fprintf(stderr,"\nErreur: une erreur est survenue lors de la creation du buffer.\n");
			exit(EXIT_CODE_ERROR_BUILD_BUFFER);
		}
		char* finalbuf2 = safe_malloc((jsize3+1)*sizeof(char));
		jsize3 = json_dumpb(trb_root_final, finalbuf2, jsize3, args->prettify?JSON_INDENT(4):JSON_COMPACT);
		if (jsize3 == 0) {
			fprintf(stderr,"\nErreur: une erreur est survenue lors de la creation du buffer.\n");
			exit(EXIT_CODE_ERROR_BUILD_BUFFER);
		}
		
		// on formate les sauts de ligne
		size_t new_size = 0;
		char* bufferc = convert_line_feed(finalbuf2, jsize3, &new_size, args->crlf, args->verbose);
		if (bufferc!=NULL) {
			finalbuf2 = bufferc;
			jsize3 = new_size;
		}
		
		// si le fichier d'output est spécifié
		if (args->output!=NULL) {
			if (args->verbose) fprintf(stderr,"[debug] Ecriture du buffer dans le fichier \"%s\"...",args->output);
			
			// on l'a déjà ouvert, reste plus qu'à écrire les données
			if (fwrite(finalbuf2,sizeof(char),jsize3,trb)!=jsize3) {
				if (args->verbose) fprintf(stderr,"\n");
				bad_io_error(args->output);
			}
			
			if (args->verbose) fprintf(stderr," OK\n");
		}
		
		// si --stdout est spécifié
		if (args->stdoutconsole) {
			if (args->verbose) fprintf(stderr,"[debug] Ecriture du buffer sur la console...");
			
			// on écrit sur la console
			if (fwrite(finalbuf2,sizeof(char),jsize3,stdout)!=jsize3) {
				if (args->verbose) fprintf(stderr,"\n");
				bad_io_error(args->output);
			}
			
			if (args->verbose) fprintf(stderr," OK\n");
		}
		
		// on ferme le fichier trb
		if (args->output!=NULL) fclose(trb);
		
		// on libère la mémoire
		if (args->verbose) fprintf(stderr,"[debug] Release de la memoire\n");
		free(finalbuf);
		free(finalbuf2);
		free(carUIDs);
		free(carUIDs2);
		free(levels);
		for (size_t i = 0; i < _index2; i++) free(crdbs[i]);
		free(crdbs);
		json_decref(trb_root_final);
		json_decref(scb_root);
		json_decref(nsb_root);
		free(scb_buffer);
		free(nsb_buffer);
		
		if (args->verbose) fprintf(stderr,"[debug] Fin de la contruction du fichier trb\n");
		
		
	// [en construction]
	} else if (args->command==CMD_SIG) {
	
	// [en construction]
	} else if (args->command==CMD_GZIP) {
		
	// [en construction]
	} else if (args->command==CMD_UNGZIP) {
		
	}
	
	// on libère les arguments
	free(args);
	
	return 0;
}




/**********************\
*                      *
*      FUNCTION        *
*                      *
\**********************/

// opération safe
void *safe_malloc(size_t n) {
	void *p = malloc(n);
	if (p == NULL) {
		fprintf(stderr,"Erreur: impossible d'allouer de la memoire (%s, %zu bytes).\n",strerror(errno),n);
		exit(EXIT_CODE_BAD_ALLOC_MEMORY);
	}
	return p;
}
void *safe_calloc(size_t n_items, size_t item_size) {
	void *p = calloc(n_items, item_size);
	if (p == NULL) {
		fprintf(stderr,"Erreur: impossible d'allouer de la memoire (%s, %zu bytes).\n",strerror(errno),n_items*item_size);
		exit(EXIT_CODE_BAD_ALLOC_MEMORY);
	}
	return p;
}
void *safe_realloc(void *ptr, size_t size) {
	void * new_ptr = realloc(ptr, size);
	if (size != 0 && ptr == NULL) {
		fprintf(stderr,"Erreur: impossible d'allouer de la memoire (%s, %zu bytes).\n",strerror(errno),size);
		exit(EXIT_CODE_BAD_ALLOC_MEMORY);
	}
	return new_ptr;
}
FILE* safe_fopen(const char *filename, const char *accessMode, int throw_error) {
	FILE* file = fopen(filename, accessMode);
	if (file==NULL && throw_error) {
		fprintf(stderr,"Erreur: impossible d'ouvrir le fichier \"%s\".",filename);
		exit(EXIT_CODE_IO_FILE);
	}
	return file;
}
json_t* safe_json_loadb(uint8_t* buffer, size_t size, size_t flag) {
	json_error_t error;
	json_t *root = json_loadb(buffer, size, flag, &error);
	if (root == NULL) {
		fprintf(stderr,"\nErreur: Erreur de Syntaxe ligne %d: %s\n", error.line, error.text);
		exit(EXIT_CODE_ERROR_JSON);
	}
	return root;
}




// convertion en nombre
typedef enum {
    STR2INT_SUCCESS,
    STR2INT_OVERFLOW,
    STR2INT_UNDERFLOW,
    STR2INT_INCONVERTIBLE
} str2int_errno;

/**
 * @robuste
 * _str2long : permet de convertir une chaine de caractères en nombre
 * 
 * @param [out] out - le nombre qui sera renvoyé en sorti
 * @param [in] s - la chaine de caractères
 * @param [in] base - la base
 * @param [in] isint - si 1 alors la plage est réduit entre INT_MIN et INT_MAX
 * 
 * @return retourne l'état de l'opération
 */
str2int_errno _str2long(long *out, char *s, int base, int isint) {
    char *end;
    if (s[0] == '\0' || isspace(s[0]))
        return STR2INT_INCONVERTIBLE;
    errno = 0;
    long l = strtol(s, &end, base);
	long maxlim = isint ? INT_MAX : LONG_MAX;
	long minlim = isint ? INT_MIN : LONG_MIN;
    if (l > maxlim || (errno == ERANGE && l == LONG_MAX))
        return STR2INT_OVERFLOW;
    if (l < minlim || (errno == ERANGE && l == LONG_MIN))
        return STR2INT_UNDERFLOW;
    if (*end != '\0')
        return STR2INT_INCONVERTIBLE;
    *out = l;
    return STR2INT_SUCCESS;
}

/**
 * @robuste
 * str2long : permet de convertir une chaine de caractères en nombre
 * 
 * @param [out] out - le nombre qui sera renvoyé en sorti
 * @param [in] s - la chaine de caractères
 * @param [in] base - la base
 * @param [in] isint - si 1 alors la plage est réduit entre INT_MIN et INT_MAX
 * 
 * @throw quitte le programme avec le code erreur EXIT_CODE_BAD_NUMBER si la convertion à échouer
 */
void str2long(long *out, char *s, int base, int isint) {
	str2int_errno r = _str2long(out, s, base, isint);
	if (r==STR2INT_SUCCESS) return;
	if (r==STR2INT_OVERFLOW) {
		fprintf(stderr,"Erreur: \"%s\" est trop grand (overflow).\n");
		exit(EXIT_CODE_BAD_NUMBER);
	}
	if (r==STR2INT_UNDERFLOW) {
		fprintf(stderr,"Erreur: \"%s\" est trop petit (underflow).\n");
		exit(EXIT_CODE_BAD_NUMBER);
	}
	if (r==STR2INT_INCONVERTIBLE) {
		fprintf(stderr,"Erreur: \"%s\" est inconvertible.\n");
		exit(EXIT_CODE_BAD_NUMBER);
	}
	fprintf(stderr,"Erreur: \"%s\", une erreur est survenue.\n");
	exit(EXIT_CODE_BAD_NUMBER);
}




/**
 * print_hex_wiew : permet d'afficher les buffer de manière jolie comme ceci :
 * 
 * ,----------+-------------------------------------------------+------------------,
 * | 00000010 | 73 61 6C 75 74 73 61 6C 75 74 73 61 6C 75 74 73 | salutsalutsaluts |
 * | 00000020 | 61 6C 75 74 73 61 6C 75 74 73 61 6C 75 74 73 61 | alutsalutsalutsa |
 * | 00000030 | 6C 75 74 73 61 6C 75 74 73 61 6C 75 74 73 61 6C | lutsalutsalutsal |
 * | 00000040 | 75 74 73 61 6C 75 74 73 61 6C 75 74 73 61 6C 75 | utsalutsalutsalu |
 * | 00000050 | 74 73 61 6C 75 74 73 61 6C 75 74 73 61 6C 75 74 | tsalutsalutsalut |
 * | 00000060 | 73 61 6C 75 74 73 61 6C 75 74 73 61 6C 75 74 73 | salutsalutsaluts |
 * | 00000070 | 61 6C 75 74 62 6F 6E 6A 6F 75 72 0A             | alutbonjour.     |
 * '----------+-------------------------------------------------+------------------'
 * 
 * @param [in] buffer - le buffer à afficher
 * @param [in] size - la taille du buffer
 */
void print_hex_view(char *buffer, int size) {

	if (buffer == NULL) return;
	
	int j = 0;
	int line = 0x10;
	
	printf(",");
	for (int i = 0; i < 8 + 2; i++) printf("-");
	printf("+");
	for (int i = 0; i < 0x10*3 + 1; i++) printf("-");
	printf("+");
	for (int i = 0; i < 5 + 0x10 - 3; i++) printf("-");
	printf(",\n");
	
	while (1) {
		
		int u = j;
		printf("| %08X | ",line);
		for (int i = 0; i < 0x10; i++) {
			if (u > size-1) {
				printf("   ");
				continue;
			}
			printf("%02X ",(unsigned char)buffer[u]);
			u++;
		}
		printf("| ");
		for (int i = 0; i < 0x10; i++) {
			if (j > size-1) {
				printf(" ");
				continue;
			}
			if (isspace(buffer[j]) || !isprint(buffer[j])) {
				printf(".");
				j++;
				continue;
			}
			printf("%c",buffer[j]);
			j++;
		}
		
		printf(" |\n");
		line += 0x10;
		
		if (j > size-1) break;
	}
	
	printf("'");
	for (int i = 0; i < 8 + 2; i++) printf("-");
	printf("+");
	for (int i = 0; i < 0x10*3 + 1; i++) printf("-");
	printf("+");
	for (int i = 0; i < 5 + 0x10 - 3; i++) printf("-");
	printf("'\n");
	
}


/**
 * json_replace : permet de remplacer récursivement la valeur d'une clé par un autre valeur
 *
 * @param [in/out] o - l'objet JSON
 * @param [in] k - la clé
 * @param [in] la nouvelle valeur
 * 
 * @throw quitte le programme avec lde code erreur EXIT_CODE_ERROR_JSON lors d'une erreur JSON
 */
void json_replace(json_t* o, char* k, json_t* r) {
	if (json_is_object(o)!=0) {
		const char *key;
		json_t *value;
		json_object_foreach(o, key, value) {
			if (strcmp(key,k)==0) {
				if (json_object_set(o, key, r)<0) {
					fprintf(stderr,"Erreur: une erreur est survenue.\n");
					exit(EXIT_CODE_ERROR_JSON);
				}
			} else {
				json_replace(value,k,r);
			}
		}
	} else if (json_is_array(o)!=0) {
		size_t index;
		json_t *value;
		json_array_foreach(o, index, value) {
			json_replace(value,k,r);
		}
	}
}

/**
 * convert_line_feed : permet de convertir des saut de ligne LF (Unix) en CRLF (Windows)
 *
 * @param [in] buffer - le buffer qui contient les données
 * @param [in] size - la taille du buffer
 * @param [out] new_size - la nouvelle taille du buffer
 * @param [in] crlf - si 1 alors on converti sinon on ignore
 * @param [in] verbose - si 1 alors on affiche sur la console ce qu'il se passe
 *
 * @return renvoie l'adresse du nouveau buffer (renvoie NULL si rien ne s'est passé)
 */
char* convert_line_feed(char *buffer, size_t size, size_t *new_size, int crlf, int verbose) {
	if (crlf) {
		if (verbose) fprintf(stderr,"[debug] Retour de ligne CRLF (Windows)\n");
		size_t newline = 0;
		for (size_t i = 0; i < size; i++) {
			if (buffer[i]=='\n') newline++;
		}
		char *buffer2 = safe_malloc((size+newline)*sizeof(char));
		size_t index = 0;
		for (size_t i = 0; i < size; i++) {
			if (buffer[i]=='\n') buffer2[index++] = '\r';
			buffer2[index++] = buffer[i];
		}
		free(buffer);
		buffer = buffer2;
		*new_size = index;
		return buffer;
	} else {
		if (verbose) fprintf(stderr,"[debug] Retour de ligne LF (Unix)\n");
	}
	return NULL;
}

/**
 * bad_io_error : permet de throw une erreur IO
 * @param [in] filename - le nom du fichier où l'erreur s'est produit
 */
void bad_io_error(char *filename) {
	fprintf(stderr,"Erreur: une erreur I/O est survenue sur le fichier \"%s\".\n",filename);
	exit(EXIT_CODE_IO_ERROR);
}

/**
 * bad_arguments : permet de throw une erreur d'arguments
 * @param [in] k - l'argument qui a posé problème
 * @param [in] m - le message type (@TODO: énumération ou macro define)
 */
void bad_arguments(char*k,int m) {
	if (m==0) {
		fprintf(stderr,"Erreur: l'option \"%s\" n'a pas de valeur.\nUtilisez '--help' pour afficher l'aide.\n",k);
	} else if (m==1) {
		fprintf(stderr,"Erreur: l'option \"%s\" est incompatible avec les options actuelles.\nUtilisez '--help' pour afficher l'aide.\n",k);
	} else if (m==2) {
		fprintf(stderr,"Erreur: l'option \"%s\" est inconnue.\nUtilisez '--help' pour afficher l'aide.\n",k);
	} else if (m==3) {
		fprintf(stderr,"Erreur: la commande \"%s\" est inconnue.\nUtilisez '--help' pour afficher l'aide.\n",k);
	} else if (m==4) {
		fprintf(stderr,"Erreur: l'option \"%s\" est obligatoire.\nUtilisez '--help' pour afficher l'aide.\n",k);
	} else {
		fprintf(stderr,"Erreur: \"%s\", une erreur est survenue.\nUtilisez '--help' pour afficher l'aide.\n",k);
	}
	exit(EXIT_CODE_BAD_ARGUMENT);
}

/**
 * get_arguments : permet de parse les arguments
 *
 * @param [in] argc - le nombre d'arguments
 * @param [in] argv - les arguments
 *
 * @return retourne une structure de type arguments
 */
arguments* get_arguments(int argc, char **argv) {
	
	// on créé l'objet en mettant tout à 0 sauf pour level
	arguments* args = (arguments*)safe_calloc(1,sizeof(arguments));
	args->level = Z_DEFAULT_COMPRESSION;
	
	// si le 1er correspond à l'aide alors on affiche le copyright ainsi que l'aide
	if ((strcasecmp(argv[1],"-h")==0) || (strcasecmp(argv[1],"--help")==0)) {
		copyright();
		help();
		exit(0);
	}
	
	// sinon on regarde si le 1er argument est valide
	args->command = (strcasecmp(argv[1],"unpack")==0)?CMD_UNPACK:(strcasecmp(argv[1],"pack")==0)?CMD_PACK:(strcasecmp(argv[1],"buildtrb")==0)?CMD_BUILDTRB:(strcasecmp(argv[1],"signature")==0)?CMD_SIG:(strcasecmp(argv[1],"gzip")==0)?CMD_GZIP:(strcasecmp(argv[1],"ungzip")!=0)?CMD_UNGZIP:-1;
	
	// sinon on affiche une erreur
	if (args->command < 0) {
		bad_arguments(argv[1],3);
	}
	
	// on commence à parser
	for (int i = 2; i < argc; i++) {
		if ((strcasecmp(argv[i],"-i")==0) || (strcasecmp(argv[i],"--input")==0)) {
			if (i+1 > argc-1) {
				bad_arguments(argv[i],0);
			}
			i++;
			args->input = argv[i];
		} else if ((strcasecmp(argv[i],"-o")==0) || (strcasecmp(argv[i],"--output")==0)) {
			if (i+1 > argc-1) {
				bad_arguments(argv[i],0);
			}
			i++;
			args->output = argv[i];
		} else if ((strcasecmp(argv[i],"-p")==0) || (strcasecmp(argv[i],"--prettify")==0)) {
			args->prettify = 1;
		} else if ((strcasecmp(argv[i],"-m")==0) || (strcasecmp(argv[i],"--minify")==0)) {
			args->minify = 1;
		} else if ((strcasecmp(argv[i],"-s")==0) || (strcasecmp(argv[i],"--stdout")==0)) {
			args->stdoutconsole = 1;
		} else if ((strcasecmp(argv[i],"-v")==0) || (strcasecmp(argv[i],"--verbose")==0)) {
			args->verbose = 1;
		} else if ((strcasecmp(argv[i],"--folder")==0)) {
			if (i+1 > argc-1) {
				bad_arguments(argv[i],0);
			}
			i++;
			args->folder = argv[i];
			if (args->folder[strlen(args->folder)-1]=='\\') args->folder[strlen(args->folder)-1]='\0';
		} else if ((strcasecmp(argv[i],"--scb")==0)) {
			if (i+1 > argc-1) {
				bad_arguments(argv[i],0);
			}
			i++;
			args->scb = argv[i];
		} else if ((strcasecmp(argv[i],"--nsb")==0)) {
			if (i+1 > argc-1) {
				bad_arguments(argv[i],0);
			}
			i++;
			args->nsb = argv[i];
		} else if ((strcasecmp(argv[i],"--crlf")==0)) {
			args->crlf = 1;
		} else if ((strcasecmp(argv[i],"-l")==0) || (strcasecmp(argv[i],"--level")==0)) {
			args->level = -1;
			long l = -1;
			str2long(&l, argv[i], 10, 0);
			args->level = (int)l;
			if (args->level < 1 || args->level > 9) {
				fprintf(stderr,"Erreur: le level de compression doit se situer entre 0 et 9.\n");
			}
		} else if ((strcasecmp(argv[i],"-t")==0) || (strcasecmp(argv[i],"--timestamp")==0)) {
			args->timestamp = -1;
			str2long(&args->timestamp, argv[i], 10, 1);
		} else if ((strcasecmp(argv[i],"-h")==0) || (strcasecmp(argv[i],"--help")==0)) {
			bad_arguments(argv[i],1);
		} else {
			bad_arguments(argv[i],2);
		}
	}
	
	// on retourne l'objet
	return args;
}


void copyright() {
	printf("Packer\nCopyright (c) 2021, Flammrock\n\n");
}
void help() {
	printf("Usage: \n");
	
	printf("\tPacker unpack {OPTIONS}\n\n");
	printf("\t\t%-25s%s","-i, --input=VALUE","Le fichier pack (nsb, scb, trb, ...).\n");
	printf("\t\t%-25s%s","-o, --output=VALUE","Le fichier de sortie (sous format JSON).\n");
	printf("\t\t%-25s%s","-p, --prettify","Beautifie le JSON.\n");
	printf("\t\t%-25s%s","-m, --minify","Minifie le JSON.\n");
	printf("\t\t%-25s%s","-s, --stdout","Affichage sur la console.\n");
	printf("\t\t%-25s%s","-s, --verbose","Afficher toutes les informations.\n");
	printf("\n\n");
	
	printf("\tPacker pack {OPTIONS}\n\n");
	printf("\t\t%-25s%s","-i, --input=VALUE","Le fichier JSON.\n");
	printf("\t\t%-25s%s","-o, --output=VALUE","Le fichier de sortie.\n");
	printf("\t\t%-25s%s","-p, --prettify","Beautifie le JSON.\n");
	printf("\t\t%-25s%s","-m, --minify","Minifie le JSON.\n");
	printf("\t\t%-25s%s","-s, --stdout","Affichage sur la console.\n");
	printf("\t\t%-25s%s","-s, --verbose","Afficher toutes les informations.\n");
	printf("\n\n");
	
	printf("\tPacker buildtrb {OPTIONS}\n\n");
	printf("\t\t%-25s%s","--scb=VALUE","Le fichier pack SCB ou le fichier unpack SCB.txt.\n");
	printf("\t\t%-25s%s","--nsb=VALUE","Le fichier pack NSB ou le fichier unpack NSB.txt.\n");
	printf("\t\t%-25s%s","-o, --output=VALUE","Le fichier de sortie TRB.txt.\n");
	printf("\t\t%-25s%s","-p, --prettify","Beautifie le JSON.\n");
	printf("\t\t%-25s%s","-m, --minify","Minifie le JSON.\n");
	printf("\t\t%-25s%s","-s, --stdout","Affichage sur la console.\n");
	printf("\t\t%-25s%s","-s, --verbose","Afficher toutes les informations.\n");
	printf("\n\n");
	
	printf("\tPacker signature {OPTIONS}\n\n");
	printf("\t\t%-25s%s","-i, --input=VALUE","Le fichier pack (nsb, scb, ...) ou le fichier unpack (nsb.txt, scb.txt, ...).\n");
	printf("\t\t%-25s%s","-o, --output=VALUE","Le fichier de sortie qui contiendra la signature (SHA1).\n");
	printf("\t\t%-25s%s","-s, --stdout","Affichage sur la console.\n");
	printf("\t\t%-25s%s","-s, --verbose","Afficher toutes les informations.\n");
	printf("\n\n");
	
	printf("\tPacker gzip {OPTIONS}\n\n");
	printf("\t\t%-25s%s","-i, --input=VALUE","Le fichier unpack.\n");
	printf("\t\t%-25s%s","-o, --output=VALUE","Le fichier de sortie au format gzip (pack).\n");
	printf("\t\t%-25s%s","-l, --level=VALUE","Le niveau de compression entre 1 et 9.\n");
	printf("\t\t%-25s%s","-t, --timestamp=VALUE","La date qui sera mis dans le header du fichier gzip.\n");
	printf("\t\t%-25s%s","-s, --stdout","Affichage sur la console.\n");
	printf("\t\t%-25s%s","-s, --verbose","Afficher toutes les informations.\n");
	printf("\n\n");
	
	printf("\tPacker ungzip {OPTIONS}\n\n");
	printf("\t\t%-25s%s","-i, --input=VALUE","Le fichier au format gzip (pack).\n");
	printf("\t\t%-25s%s","-o, --output=VALUE","Le fichier de sortie unpack.\n");
	printf("\t\t%-25s%s","-s, --stdout","Affichage sur la console.\n");
	printf("\t\t%-25s%s","-s, --verbose","Afficher toutes les informations.\n");
	printf("\n\n");
	
}


/**
 * gzcheck : permet de savoir si un fichier est un .gz
 *
 * @param [in] filename - le nom de fichier
 *
 * @return retourne 0 si le fichier est un .gz sinon -1
 */
int gzcheck(unsigned char *filename) {
	FILE* file = fopen(filename,"rb");
	if (file==NULL) return -1;
	unsigned char id1=0;
	unsigned char id2=0;
	if (fread(&id1, 1, 1, file)!=1) {fclose(file);return 0;}
	if (fread(&id2, 1, 1, file)!=1) {fclose(file);return 0;}
	fclose(file);
	return (id1==0x1F && id2==0x8B)?0:-1;
}

/**
 * gzloadfile : permet de charger un fichier .gz
 *
 * @param [in] filename - le nom de fichier
 * @param [out] buffersize - la taille du buffer renvoyé
 * @param [in] check - si 1 alors on check si le fichier est un .gz (throw une erreur sinon)
 *                     si 0 alors aucun check n'est fait, le fichier n'est pas un .gz, le contenu non-unpack sera renvoyé
 *
 * @return retourne le contenu du fichier unpack (si fichier .gz) sinon non-unpack
 */
uint8_t* gzloadfile(unsigned char *filename, size_t* buffersize, int check) {
	
	if (buffersize!=NULL) *buffersize = 0;
	
	if (check && gzcheck(filename)!=0) {
		fprintf(stderr,"Erreur: \"%s\" n'est pas un fichier gzip valide\n",filename);
		return NULL;
	}
	
	
	gzFile fp;
    uint8_t line[CHUNK];
	for (int i = 0; i < CHUNK; i++) line[i] = '\0';

    fp = gzopen(filename, "r");
	if (fp == Z_NULL) {
		fprintf(stderr,"Erreur: impossible d'ouvrir \"%s\"\n",filename);
		return NULL;
	}
	
	size_t size = 2;
	size_t index = 0;
	uint8_t *data = (uint8_t*)safe_malloc((size+1)*sizeof(uint8_t));
	
	int r = 0;
	do {
		if ((r=gzread(fp, line, CHUNK)) == 0) {
			gzclose(fp);
			fprintf(stderr,"Erreur: decompression impossible de \"%s\"\n",filename);
			return NULL;
		}
		for (int i = 0; i < r; i++) {
			data[index++] = line[i];
			if (index >= size-1) {
				size *= 2;
				data = (uint8_t*)safe_realloc(data,(size+1)*sizeof(uint8_t));
			}
		}
	} while (!gzeof(fp));
	
	data[index] = '\0';
	
	int errnum = 0;
	const char *msg = gzerror(fp, &errnum);
	if (errnum==Z_ERRNO) {
		free(data);
		gzclose(fp);
		fprintf(stderr,"Erreur: I/O Erreur lors de la lecture du fichier \"%s\"\n",filename);
		return NULL;
	} else if (errnum!=0) {
		free(data);
		gzclose(fp);
		fprintf(stderr,"Erreur: decompression impossible de \"%s\"\n",filename);
		return NULL;
	}
	
	if (buffersize!=NULL) *buffersize = index;

    gzclose(fp);
	return data;
	
}

/**
 * gzcompressdata : permet de compresser les données sous format gzip dans un fichier avec un header personnalisé
 *
 * inspiré de ce tuto : https://zlib.net/zlib_how.html (Grand à merci à eux pour leur travail)
 *
 * @param [in] dest - fichier où sera écrit les données pack
 * @param [in] source - le buffer qui sera pack et écrit dans le fichier
 * @param [in] len - la taille du buffer
 * @param [in] header - le header du gzip qui sera écrit
 * @param [in] level - le niveau de compression (entre 1 et 9)
 *
 * @return retourne 0 si succès et sinon retourne -1 en cas d'erreur
 */
int gzcompressdata(FILE *dest, unsigned char* source, size_t len, gz_header *header, int level) {
    int ret, flush;
    unsigned have;
    z_stream strm;
    unsigned char out[CHUNK];
	
	unsigned char *sourcep = source;


    /* allocate deflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    ret = deflateInit2(&strm, level, Z_DEFLATED, 15 | 16, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK)
        return ret;
	if (header!=NULL) {
	ret = deflateSetHeader(&strm, header);
		if (ret != Z_OK)
			return ret;
	}

    /* compress until end of file */
    do {
        strm.avail_in = len<CHUNK?len:CHUNK;
		len -= strm.avail_in;
        flush = (len<=0) ? Z_FINISH : Z_NO_FLUSH;
        strm.next_in = sourcep;
		sourcep += strm.avail_in;
        /* run deflate() on input until output buffer not full, finish
           compression if all of source has been read in */
        do {

            strm.avail_out = CHUNK;
            strm.next_out = out;

            ret = deflate(&strm, flush);    /* no bad return value */
            assert(ret != Z_STREAM_ERROR);  /* state not clobbered */

            have = CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
                (void)deflateEnd(&strm);
                return Z_ERRNO;
            }


        } while (strm.avail_out == 0);
        assert(strm.avail_in == 0);     /* all input will be used */


        /* done when last data in file processed */
    } while (flush != Z_FINISH);
    assert(ret == Z_STREAM_END);        /* stream will be complete */

    /* clean up and return */
    (void)deflateEnd(&strm);
    return Z_OK;
}

/**
 * gzwritestream : permet d'écrire des données pack dans un stream
 *
 * @param [in] stream - le stream dans lequel les données seront écrit (peut être un fichier, ou bien stdout, stderr, etc..)
 * @param [in] buffer - le buffer qui sera pack puis écrit dans le stream
 * @param [in] buffersize - la taille du buffer
 * @param [in] level - le niveau de compression (doit être compris entre 1 et 9) (aucun check fait pour vérifier que le level est dans cet interval)
 *
 * @return retourne -1 en cas d'erreur sinon 0 (succès)
 */
int gzwritestream(FILE *stream, uint8_t *buffer, size_t buffersize, int level) {
	if (buffer == NULL) return -1;
	gz_header header;
	memset(&header, 0, sizeof(gz_header));
	header.os=19; // OS Android
	if (gzcompressdata(stream, buffer, buffersize, &header, level) != Z_OK) return -1;
	return 0;
}

/**
 * gzwritestream : permet d'écrire des données pack dans un fichier
 *
 * @param [in] filename - le nom de fichier dans lequel les données seront écrit
 * @param [in] buffer - le buffer qui sera pack puis écrit dans le fichier
 * @param [in] buffersize - la taille du buffer
 * @param [in] level - le niveau de compression (doit être compris entre 1 et 9) (aucun check fait pour vérifier que le level est dans cet interval)
 *
 * @return retourne -1 en cas d'erreur sinon 0 (succès)
 */
int gzwritefile(unsigned char *filename, uint8_t *buffer, size_t buffersize, int level) {
	
	if (buffer == NULL) return -1;
	
	FILE* file = fopen(filename, "wb");
	if (file == NULL) {
		fprintf(stderr,"Erreur: impossible d'ouvrir \"%s\"\n",filename);
		return -1;
	}
	
	int r = gzwritestream(file, buffer, buffersize, level);
	fclose(file);
	
	return r;
	
}

/**
 * gzprintfile : permet d'afficher les données unpack d'un .gz sur la console
 
 * @param [in] filename - le nom de fichier
 *
 * @return retourne -1 en cas d'erreur sinon 0 (succès)
 */
int gzprintfile(unsigned char *filename) {
	uint8_t *data = gzloadfile("scb",NULL,0);
	if (data == NULL) return -1;
	printf("%s\n",data);
	free(data);
	return 0;
}



/**
 * packer_get_data : permet de récupérer le buffer unpack ainsi que la signature associé à partir d'un fichier pack ou unpack
 *
 * @param [in] filename - le nom de fichier
 * @param [out] sizesig - la taille de la signature
 * @param [out] sizejson - la taille du JSON
 * @param [in] verbose - permet de debug
 * @param [in] prettify - permet de beautifier le JSON
 * @param [in] crlf - si 1 alors les sauts de lignes LF (Unix) seront converti en sauf de lignes CRLF (Windows)
 *
 * @eturn retourne le buffer, les {sizesig} octets sont ceux de la signature, les octets restant sont ceux du JSON (beautifier ou minifié)
 */
uint8_t* packer_get_data(char *filename, size_t* sizesig, size_t* sizejson, int verbose, int prettify, int crlf) {
	
	uint8_t* signature = NULL;
	size_t sizesignature = 0;
	uint8_t *data = NULL;
	size_t size = 0;
	uint8_t *jdata = NULL;
	size_t jsize = 0;
	
	// on regarde si le fichier est déjà gzippé
	int ispacked = 0;
	if (gzcheck(filename)==0) {
		if (verbose) fprintf(stderr,"[debug] Le fichier \"%s\" est pack\n",filename);
		ispacked = 1;
	} else {
		if (verbose) fprintf(stderr,"[debug] Le fichier \"%s\" est unpack\n",filename);
	}
	
	// on récupère le contenu du fichier (gzippé ou non)
	if (verbose) fprintf(stderr,"[debug] Chargement de \"%s\"...",filename);
	data = gzloadfile(filename,&size,0);
	if (verbose) fprintf(stderr," OK\n");
	if (verbose) fprintf(stderr,"[debug] Taille Data : %zu Octets\n",size);
	
	// s'il est gzippé, on récupère le JSON
	if (ispacked) {
		if (verbose) fprintf(stderr,"[debug] Recuperation du JSON...",filename);
		jdata = packer_get_jsonstring(data, size, &jsize);
		if (verbose) fprintf(stderr," OK\n");
		if (verbose) fprintf(stderr,"[debug] Taille JSON : %zu Octets\n",jsize);
		
	// sinon le fichier n'est pas gzippé est correspond déjà au JSON
	} else {
		jsize = size;
		jdata = data;
	}
	
	
	// on parse le JSON
	if (verbose) fprintf(stderr,"[debug] Parsage du JSON...");
	json_error_t error;
	json_t *root = json_loadb(jdata, jsize, 0, &error);
	
	// s'il y a une erreur, on affiche le problème
	if (root == NULL) {
		fprintf(stderr,"\nErreur: Erreur de Syntaxe ligne %d: %s\n", error.line, error.text);
		exit(EXIT_CODE_ERROR_JSON);
	}
	if (verbose) fprintf(stderr," OK\n");
	
	// on indique comment le JSON va être formaté
	if (verbose && prettify) fprintf(stderr,"[debug] Le JSON est beautifier (prettify)\n");
	if (verbose && !prettify) fprintf(stderr,"[debug] Le JSON est minifier\n");
	
	
	// si le fichier est gzippé, on récupère la signature pour vérifier sa validité
	if (ispacked) {
		if (verbose) fprintf(stderr,"[debug] Recuperation de la signature...",filename);
		signature = packer_get_signature(data, size, &sizesignature);
		if (verbose) fprintf(stderr," OK\n");
		if (verbose) fprintf(stderr,"[debug] Signature : %s\n",signature);
		if (verbose) fprintf(stderr,"[debug] Verification de la signature...\n");
		
		char _hexdigest[41];
		char _hexdigest2[41];
		if (verbose) fprintf(stderr,"[debug] Calcul de la signature...");
		int r = hmacsha1(_hexdigest, "4cPw3ZyC", jdata, jsize);
		int r2 = hmacsha1(_hexdigest2, "UDMZr24F", jdata, jsize);
		if (verbose) fprintf(stderr," OK\n");
		if (r==0)
			if (verbose) fprintf(stderr,"[debug] HMAC SHA1 OFFLINE: %s\n",_hexdigest);
		if (r2==0)
			if (verbose) fprintf(stderr,"[debug] HMAC SHA1 ONLINE : %s\n",_hexdigest2);
		
		if (r!=0) {
			fprintf(stderr,"\nErreur: une erreur est survenue lors du calcul.\n");
			exit(EXIT_CODE_ERROR_SIGNATURE_CALC);
		}
		
		if ((r==0 && strcasecmp(_hexdigest,signature)==0) || (r2==0 && strcasecmp(_hexdigest2,signature)==0)) {
			if (verbose) fprintf(stderr,"[debug] Signature correct!\n");
		} else {
			if (verbose) fprintf(stderr,"[debug] Signature invalide!\n");
		}
	}
	
	
	// on créé le buffer final
	if (verbose) fprintf(stderr,"[debug] Creation buffer...");
	size_t jsize2 = json_dumpb(root, NULL, 0, prettify?JSON_INDENT(4):JSON_COMPACT);
	if (jsize2 == 0) {
		fprintf(stderr,"\nErreur: une erreur est survenue lors de la creation du buffer.\n");
		exit(EXIT_CODE_ERROR_BUILD_BUFFER);
	}
	if (verbose) fprintf(stderr," OK\n");
	if (verbose) fprintf(stderr,"[debug] Taille Buffer : %zu Octets\n",jsize2+41);
	uint8_t* buf = safe_malloc(jsize2+41);
	
	// on stringify le JSON formaté correctement
	jsize2 = json_dumpb(root, buf+41, jsize2, prettify?JSON_INDENT(4):JSON_COMPACT);
	if (jsize2 == 0) {
		fprintf(stderr,"\nErreur: une erreur est survenue lors de la creation du buffer.\n");
		exit(EXIT_CODE_ERROR_BUILD_BUFFER);
	}
	
	
	
	// on calcul la signature à partir du JSON (minifié ou beautifié)
	char hexdigest[41];
	char hexdigest2[41];
	if (verbose) fprintf(stderr,"[debug] Calcul de la signature...");
	int r = hmacsha1(hexdigest, "4cPw3ZyC", buf+41, jsize2);
	int r2 = hmacsha1(hexdigest2, "UDMZr24F", buf+41, jsize2);
	if (verbose) fprintf(stderr," OK\n");
	if (r==0)
		if (verbose) fprintf(stderr,"[debug] HMAC SHA1 OFFLINE: %s\n",hexdigest);
	if (r2==0)
		if (verbose) fprintf(stderr,"[debug] HMAC SHA1 ONLINE : %s\n",hexdigest2);
	
	if (r!=0) {
		fprintf(stderr,"\nErreur: une erreur est survenue lors du calcul.\n");
		exit(EXIT_CODE_ERROR_SIGNATURE_CALC);
	}
	
	// on ajoute la signature dans le buffer
	for (size_t i = 0; i < 40; i++) buf[i] = hexdigest[i];
	buf[40] = '\n';
	
	// on met à jour les tailles
	*sizejson = jsize2;
	*sizesig = 40;
	
	// on formate les sauts de ligne
	size_t new_size = 0;
	char* bufferc = convert_line_feed(buf, jsize2+41, &new_size, crlf, verbose);
	if (bufferc!=NULL) {
		buf = bufferc;
		*sizejson = new_size-42;/*jsize2+newline-1;*/
		*sizesig = 41;
	}
	
	// on libère la mémoire
	if (verbose) fprintf(stderr,"[debug] Release de la memoire\n",jsize2+41);
	free(data);
	if (ispacked) free(jdata);
	if (ispacked) free(signature);
	json_decref(root);
	
	// on retourne le buffer (qui contient la signature et le json)
	return buf;
}

/**
 * packer_get_signature : permet de récupérer la signature qui se trouve dans un buffer
 *
 * @param [in] buffer - le buffer qui contient la signature
 * @param [in] size - la taille du buffer
 * @param [out] sigsize - la taille de la signature
 *
 * @return retourne un buffer qui contient la signature
 */
uint8_t* packer_get_signature(uint8_t *buffer, size_t size, size_t *sigsize) {
	if (sigsize!=NULL) *sigsize = 0;
	if (buffer==NULL) return NULL;
	char *sig = (uint8_t*)safe_malloc((size+1)*sizeof(uint8_t));
	size_t index = 0;
	for (size_t i = 0; i < size; i++) {
		if (buffer[i] == '\n' || buffer[i] == '\r') break;
		sig[index++] = buffer[i];
	}
	sig[index] = '\0';
	sig = (uint8_t*)safe_realloc(sig,(index+1)*sizeof(uint8_t));
	if (sigsize!=NULL) *sigsize = index;
	return sig;
}

/**
 * packer_get_signature : permet de récupérer les données JSON qui se trouve dans un buffer (en ignorant la signature)
 *
 * @param [in] buffer - le buffer qui contient les données JSON
 * @param [in] size - la taille du buffer
 * @param [out] sigsize - la taille du JSON
 *
 * @return retourne un buffer qui contient les données JSON
 */
uint8_t* packer_get_jsonstring(uint8_t *buffer, size_t size, size_t *jsonsize) {
	if (jsonsize!=NULL) *jsonsize = 0;
	if (buffer==NULL) return NULL;
	char *json = (uint8_t*)safe_malloc((size+1)*sizeof(uint8_t));
	size_t index = 0;
	size_t i;
	for (i = 0; i < size; i++) {
		if (buffer[i] == '\n' || buffer[i] == '\r') break;
	}
	for (i++; i < size; i++) {
		json[index++] = buffer[i];
	}
	while (json[index-1]=='\0'){
		index--;
	}
	json[index] = '\0';
	json = (uint8_t*)safe_realloc(json,(index+1)*sizeof(uint8_t));
	if (jsonsize!=NULL) *jsonsize = index;
	return json;
}

/**
 * hmacsha1 : permet de calculer le hmacsha1 d'un buffer
 *
 * @param [out] hexdigest - la clé sous format hexadécimal
 * @param [out] key - la clé (en octets)
 * @param [in] data - le buffer
 * @param [in] databytes - la taille du buffer
 *
 * @return retourn 0 si succès, sinon en cas d'erreur retourne -1
 */
int hmacsha1(char *hexdigest, uint8_t* key, const uint8_t *data, size_t databytes) {

	int r = 0;
	size_t keylength = strlen(key);
	
	if (keylength > 64) {
		uint8_t newkey[21];
		char newkeyhex[41];
		r = sha1digest(newkey, newkeyhex, key, keylength);
		if (r!=0) return -1;
		newkey[20] = '\0';
		newkeyhex[40] = '\0';
		key = newkeyhex;
	}
	
	uint8_t bytes[65];
	for (int i = 0; i < 64; ++i) {
        bytes[i] = keylength > i ? key[i] : 0x00;
    }
	bytes[64] = '\0';
	
	
	unsigned char oKeyPad[65];
    unsigned char iKeyPad[65];
	for (int i = 0; i < 64; ++i) {
        oKeyPad[i] = bytes[i] ^ 0x5C;
        iKeyPad[i] = bytes[i] ^ 0x36;
    }
	oKeyPad[64] = '\0';
	iKeyPad[64] = '\0';
	
	
	uint8_t *rdata = (uint8_t*)safe_malloc((64+databytes+1)*sizeof(uint8_t));
	size_t index = 0;
	for (size_t i = 0; i < 64; i++) rdata[index++] = iKeyPad[i];
	for (size_t i = 0; i < databytes; i++) rdata[index++] = data[i];
	rdata[index] = '\0';
	
	uint8_t rdatadigest[21];
	char rdatadigesthex[41];
	r = sha1digest(rdatadigest, rdatadigesthex, rdata, index);
	if (r!=0) {
		free(rdata);
		return -1;
	}
	rdatadigest[20] = '\0';
	rdatadigesthex[40] = '\0';
	
	
	size_t rdatadigestlen = strlen(rdatadigest);
	uint8_t *rdata2 = (uint8_t*)safe_malloc((64+rdatadigestlen+1)*sizeof(uint8_t));
	size_t index2 = 0;
	for (size_t i = 0; i < 64; i++) rdata2[index2++] = oKeyPad[i];
	for (size_t i = 0; i < rdatadigestlen; i++) rdata2[index2++] = rdatadigest[i];
	rdata2[index2] = '\0';
	
	uint8_t rdatadigest2[21];
	char rdatadigesthex2[41];
	r = sha1digest(rdatadigest2, rdatadigesthex2, rdata2, index2);
	if (r!=0) {
		free(rdata);
		free(rdata2);
		return -1;
	}
	rdatadigest2[20] = '\0';
	rdatadigesthex2[40] = '\0';
	
	size_t lenr = strlen(rdatadigesthex2);
	for (int i = 0; i < lenr; i++) hexdigest[i] = rdatadigesthex2[i];
	hexdigest[40] = '\0';
	
	free(rdata);
	free(rdata2);

	return 0;

}


// Grand merci à celui qui à coder ça (un peu la flemme de le faire x) )
/*******************************************************************************
 * Teeny SHA-1
 *
 * The below sha1digest() calculates a SHA-1 hash value for a
 * specified data buffer and generates a hex representation of the
 * result.  This implementation is a re-forming of the SHA-1 code at
 * https://github.com/jinqiangshou/EncryptionLibrary.
 *
 * Copyright (c) 2017 CTrabant
 *
 * License: MIT, see included LICENSE file for details.
 *
 * To use the sha1digest() function either copy it into an existing
 * project source code file or include this file in a project and put
 * the declaration (example below) in the sources files where needed.
 ******************************************************************************/
int sha1digest(uint8_t *digest, char *hexdigest, const uint8_t *data, size_t databytes) {
#define SHA1ROTATELEFT(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

  uint32_t W[80];
  uint32_t H[] = {0x67452301,
                  0xEFCDAB89,
                  0x98BADCFE,
                  0x10325476,
                  0xC3D2E1F0};
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
  uint32_t e;
  uint32_t f = 0;
  uint32_t k = 0;

  uint32_t idx;
  uint32_t lidx;
  uint32_t widx;
  uint32_t didx = 0;

  int32_t wcount;
  uint32_t temp;
  uint64_t databits = ((uint64_t)databytes) * 8;
  uint32_t loopcount = (databytes + 8) / 64 + 1;
  uint32_t tailbytes = 64 * loopcount - databytes;
  uint8_t datatail[128] = {0};

  if (!digest && !hexdigest)
    return -1;

  if (!data)
    return -1;

  /* Pre-processing of data tail (includes padding to fill out 512-bit chunk):
     Add bit '1' to end of message (big-endian)
     Add 64-bit message length in bits at very end (big-endian) */
  datatail[0] = 0x80;
  datatail[tailbytes - 8] = (uint8_t) (databits >> 56 & 0xFF);
  datatail[tailbytes - 7] = (uint8_t) (databits >> 48 & 0xFF);
  datatail[tailbytes - 6] = (uint8_t) (databits >> 40 & 0xFF);
  datatail[tailbytes - 5] = (uint8_t) (databits >> 32 & 0xFF);
  datatail[tailbytes - 4] = (uint8_t) (databits >> 24 & 0xFF);
  datatail[tailbytes - 3] = (uint8_t) (databits >> 16 & 0xFF);
  datatail[tailbytes - 2] = (uint8_t) (databits >> 8 & 0xFF);
  datatail[tailbytes - 1] = (uint8_t) (databits >> 0 & 0xFF);

  /* Process each 512-bit chunk */
  for (lidx = 0; lidx < loopcount; lidx++)
  {
    /* Compute all elements in W */
    memset (W, 0, 80 * sizeof (uint32_t));

    /* Break 512-bit chunk into sixteen 32-bit, big endian words */
    for (widx = 0; widx <= 15; widx++)
    {
      wcount = 24;

      /* Copy byte-per byte from specified buffer */
      while (didx < databytes && wcount >= 0)
      {
        W[widx] += (((uint32_t)data[didx]) << wcount);
        didx++;
        wcount -= 8;
      }
      /* Fill out W with padding as needed */
      while (wcount >= 0)
      {
        W[widx] += (((uint32_t)datatail[didx - databytes]) << wcount);
        didx++;
        wcount -= 8;
      }
    }

    /* Extend the sixteen 32-bit words into eighty 32-bit words, with potential optimization from:
       "Improving the Performance of the Secure Hash Algorithm (SHA-1)" by Max Locktyukhin */
    for (widx = 16; widx <= 31; widx++)
    {
      W[widx] = SHA1ROTATELEFT ((W[widx - 3] ^ W[widx - 8] ^ W[widx - 14] ^ W[widx - 16]), 1);
    }
    for (widx = 32; widx <= 79; widx++)
    {
      W[widx] = SHA1ROTATELEFT ((W[widx - 6] ^ W[widx - 16] ^ W[widx - 28] ^ W[widx - 32]), 2);
    }

    /* Main loop */
    a = H[0];
    b = H[1];
    c = H[2];
    d = H[3];
    e = H[4];

    for (idx = 0; idx <= 79; idx++)
    {
      if (idx <= 19)
      {
        f = (b & c) | ((~b) & d);
        k = 0x5A827999;
      }
      else if (idx >= 20 && idx <= 39)
      {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      }
      else if (idx >= 40 && idx <= 59)
      {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      }
      else if (idx >= 60 && idx <= 79)
      {
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }
      temp = SHA1ROTATELEFT (a, 5) + f + e + k + W[idx];
      e = d;
      d = c;
      c = SHA1ROTATELEFT (b, 30);
      b = a;
      a = temp;
    }

    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
  }

  /* Store binary digest in supplied buffer */
  if (digest)
  {
    for (idx = 0; idx < 5; idx++)
    {
      digest[idx * 4 + 0] = (uint8_t) (H[idx] >> 24);
      digest[idx * 4 + 1] = (uint8_t) (H[idx] >> 16);
      digest[idx * 4 + 2] = (uint8_t) (H[idx] >> 8);
      digest[idx * 4 + 3] = (uint8_t) (H[idx]);
    }
  }

  /* Store hex version of digest in supplied buffer */
  if (hexdigest)
  {
    snprintf (hexdigest, 41, "%08x%08x%08x%08x%08x",
              H[0],H[1],H[2],H[3],H[4]);
  }

  return 0;
}
