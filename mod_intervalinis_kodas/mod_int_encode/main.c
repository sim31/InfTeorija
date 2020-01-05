#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #define WINDOWS // uzkomentuot linuxams
#ifdef WINDOWS
#include <direct.h>
#define GetCurrentDir _getcwd
#else
#include <unistd.h>
#define GetCurrentDir getcwd
#endif

#define BUFFER_SIZE 2
#define CODE_ARR_LENGTH 34

typedef struct symbol
{
    int binary_representation[16];              // bitai tokie, kaip nuskaityti is buferio
    struct symbol *next;
} Symbol;

int read_symbol_from_input(int bit_number, FILE *input_file, Symbol *symbol, unsigned char buffer[BUFFER_SIZE], int *bits_left_in_buffer,
			   int *current_buffer_byte, int *current_buffer_bit_in_byte, int left_bits[16], int *left_bits_number);
unsigned char get_mask(int current_bit);
int get_log_infimum(int k);
void get_c1_code(int k, int arr[CODE_ARR_LENGTH]);
void get_c2_code(int k, int arr[CODE_ARR_LENGTH]);

int main(int argc, char *argv[])
{
    // tikrinam vartotojo inputa konsoleje

    // blogas argumentu kiekis
    if(argc != 5 && argc!= 4){
        printf("\n\tBlogas argumentu kiekis.\n\tKreipinys i programa:\n\n");
        printf("\tmod_int_encode.exe <bitu zodyje skaicius> <koduote> <ivesties failas> [isvesties failas]\n\n");
        printf("\tBitu zodyje skaicius - nuo 1 iki 16 imtinai.\n");
        printf("\tKoduotes - c1, c2.\n");
        printf("\tIvesties failo ieskoma tame paciame kataloge, kaip ir si programa, jei nurodytas adresas nera absoliutus.\n");
        printf("\tJei isvesties failas nenurodytas, jis sukuriamas su generiniu pavadinimu\n");
        printf("\t\"output.txt\" tame paciame kataloge, kur ir ivesties failas.\n");
        printf("\tJei isvesties failo pavadinimas nurodytas, tai jis sukuriamas\n");
        printf("\ttame paciame kataloge, kaip ir ivesties failas, bet su nurodytu pavadinimu.\n");
        printf("\n\tPavyzdys su absoliuciu adresu:");
        printf("\n\tmod_int_encode.exe 8 c2 C:\\input.txt my_result.txt\n");
        printf("\n\tPavyzdys be absoliutaus adreso:");
        printf("\n\tmod_int_encode.exe 10 c1 input.txt my_result.txt\n");
        return -1;
    }

    // blogas bitu skaicius
    int bit_number = atoi(argv[1]);
    if (bit_number > 16 || bit_number < 1){
        printf("\n\n\tBlogas bitu skaicius. Bitu skaicius turi buti intervale nuo 1 iki 16 imtinai\n");
        return -1;
    }

    // bloga koduote
    if(strcmp(argv[2], "c1") && strcmp(argv[2], "c2") != 0){
        printf("\n\n\tNeteisingai pasirinkta koduote. Galimos koduotes: c1, c2.\n");
        return -1;
    }

    // input failo pavadinimo tikrinimas
    int i = 0;
    int input_file_has_abs_path = 0;
    while(argv[3][i] != '\0'){
        #ifdef WINDOWS
        if(argv[3][i] == '\\'){
            input_file_has_abs_path = 1;
        }
        #else
        if(argv[3][i] == '/'){
            input_file_has_abs_path = 1;
        }
        #endif
        i++;
    }

    char input_file_name[FILENAME_MAX];

    // jei input failas duotas be absoliutaus kelio
    if(input_file_has_abs_path == 0){
        GetCurrentDir(input_file_name, FILENAME_MAX);
        int string_end_index = 0;
        while(input_file_name[string_end_index] != '\0'){
            string_end_index++;
        }
        int i = 0;
        #ifdef WINDOWS
        input_file_name[string_end_index] = '\\';
        #else
        input_file_name[string_end_index] = '/';
        #endif
        string_end_index++;
        while(argv[3][i] != '\0'){
            input_file_name[string_end_index] = argv[3][i];
            i++;
            string_end_index++;
        }
        input_file_name[string_end_index] = '\0';
    } else {
        // jei input failas turi absoliutu kelia
        int i = 0;
        while(argv[3][i] != '\0'){
            input_file_name[i] = argv[3][i];
            i++;
        }
        input_file_name[i] = '\0';
    }

    // bandom atidaryt input faila:
    FILE *input_file;
    input_file = fopen(input_file_name, "rb");
    if(input_file == 0){
        printf("\tNepavyko rasti ivesties failo.\n");
        return -1;
    }

    // sukuriam output failo pavadinima:
    char output_file_name[FILENAME_MAX];
    if(input_file_has_abs_path == 1){
        int last_folder_index = 0;
        int i = 0;
        while(input_file_name[i] != '\0'){
            #ifdef WINDOWS
            if(input_file_name[i] == '\\')
            #else
            if(input_file_name[i] == '/')
            #endif
            {
                last_folder_index = i;
            }
            output_file_name[i] = input_file_name[i];
            i++;
        }
        // jei nenurodytas output failo pavadinimas:
        if(argc == 4){
            #ifdef WINDOWS
            output_file_name[last_folder_index] = '\\';
            #else
            output_file_name[last_folder_index] = '/';
            #endif // WINDOWS
            last_folder_index++;
            output_file_name[last_folder_index] = 'o';
            output_file_name[last_folder_index + 1] = 'u';
            output_file_name[last_folder_index + 2] = 't';
            output_file_name[last_folder_index + 3] = 'p';
            output_file_name[last_folder_index + 4] = 'u';
            output_file_name[last_folder_index + 5] = 't';
            output_file_name[last_folder_index + 6] = '.';
            output_file_name[last_folder_index + 7] = 'b';
            output_file_name[last_folder_index + 8] = 'i';
            output_file_name[last_folder_index + 9] = 'n';
            output_file_name[last_folder_index + 10] = '\0';
        } else {
            #ifdef WINDOWS
            output_file_name[last_folder_index] = '\\';
            #else
            output_file_name[last_folder_index] = '/';
            #endif // WINDOWS
            last_folder_index++;
            int i = 0;
            while(argv[4][i] != '\0'){
                output_file_name[last_folder_index] = argv[4][i];
                i++;
                last_folder_index++;
            }
            output_file_name[last_folder_index] = '\0';
        }
    } else {
        // jei input failas neturi absoliutaus adreso:
        GetCurrentDir(output_file_name, FILENAME_MAX);
        int string_end_index = 0;
        while(output_file_name[string_end_index] != '\0'){
            string_end_index++;
        }
        int i = 0;
        #ifdef WINDOWS
        output_file_name[string_end_index] = '\\';
        #else
        output_file_name[string_end_index] = '/';
        #endif
        string_end_index++;
        if(argc == 5){
            while(argv[4][i] != '\0'){
            output_file_name[string_end_index] = argv[4][i];
            i++;
            string_end_index++;
            }
            output_file_name[string_end_index] = '\0';
        } else {
            output_file_name[string_end_index] = 'o';
            output_file_name[string_end_index + 1] = 'u';
            output_file_name[string_end_index + 2] = 't';
            output_file_name[string_end_index + 3] = 'p';
            output_file_name[string_end_index + 4] = 'u';
            output_file_name[string_end_index + 5] = 't';
            output_file_name[string_end_index + 6] = '.';
            output_file_name[string_end_index + 7] = 'b';
            output_file_name[string_end_index + 8] = 'i';
            output_file_name[string_end_index + 9] = 'n';
            output_file_name[string_end_index + 10] = '\0';
        }
    }

    // sukuriam output faila:
    FILE *output_file;
    output_file = fopen(output_file_name, "wb");

    // Susitvarkem su pradiniais failais ir vartotojo inputu.

    // pagalbiniai kintamieji:
    Symbol *init_node = NULL;                           // rodykle i simboliu linked lista (t.y. zodyna)
    Symbol *current_node = NULL;                        // rodykle iteravimui per linked lista
    unsigned char buffer[BUFFER_SIZE];                  // buferis - jame laikomas nuskaitytas inputas
    int bits_left_in_buffer = 0;
    int current_buffer_byte = 0;                        // einamojo buferio baito numeris, is kurio imame bitus
    int current_buffer_bit_in_byte = 0;                 // kiek bitu liko einamajame baite dar nepaimtu
    int left_bits[16];                                  // bitai, kurie atliko skaitant buferi, t.y. ju nebeuztenka suformuoti naujam simboliui
    int left_bits_number = 0;

    init_node = malloc(sizeof(Symbol));
    current_node = init_node;


    // bandom surasti visus skirtingus simbolius faile
    int result = 0;
    while(1){
      result = read_symbol_from_input(bit_number, input_file, current_node, buffer, &bits_left_in_buffer,
					  &current_buffer_byte, &current_buffer_bit_in_byte, left_bits, &left_bits_number);
      if(result == 1){
	int already_found = 0;
	Symbol *node_to_compare = init_node;
	while(node_to_compare->next != NULL){
	  int equal_bits = 0;
	  for(i = 0; i < bit_number; i++){
	    if(current_node->binary_representation[i] == node_to_compare->binary_representation[i]){
	      equal_bits++;
	    }
	  }
	  if(equal_bits == bit_number){
	    already_found = 1;
	    break;
	  }
	  node_to_compare = node_to_compare->next;
	}

	if(!already_found){
	  current_node->next = malloc(sizeof(Symbol));
	  current_node = current_node->next;
	  current_node->next = NULL;
	}
      } else {	
	break;
      }
    }

    // suformuojam output failo header'i:
    // 1 baitas - pirmi 4 bitai is kaires - bitu kiekis simbolyje (skaiciuojama nuo nulio - 0 reiskia 1 bita, 1 - 2 bitus ir t.t.), paskutinis bitas - koduote (c1 - 0 arba c2 - 1)
    // 1 baitas - netilpusiu bitu kiekis (0 - 15)
    // 2 baitai - netilpe bitai (trukstamos vietos is galo uzpildomos nuliais)
    // 2 baitai - zodyno dydis (skaiciuojama nuo nulio - 0 reiskia 1 simboli zodyne, 1 - 2 simbolius ir t.t.)
    // neribotas baitu kiekis - zodynas. Jei zodyno simboliu suma dalosi is 8 su liekana, paskutinis baitas pripildomas iki galo nuliais.


    unsigned char buf1[6];
    
    // nurodom koduote
    unsigned char bits_and_coding = 0;
    if(strcmp(argv[2], "c2") == 0){
      bits_and_coding++;
    }
    // nurodom bitu kieki simbolyje.
    bits_and_coding += (bit_number - 1) << 4; 
    // irasom 1 baita i buferi
    buf1[0] = bits_and_coding;

    // nurodom likusiu bitu skaiciu
    buf1[1] = -1*result;

    // irasom netilpusius bitus:
    for(i = 0; i < 16; i++){
      if(left_bits[i] > 0){
	left_bits[i] = 1;
      } else {
	left_bits[i] = 0;
      }
    }
    
    buf1[2] = 0;
    int mult = 128;
    for(i = 0; i < 8; i++){
      buf1[2] += left_bits[i] * mult;
      mult = mult >> 1;
    }

    buf1[3] = 0;
    mult = 128;
    for(i = 8; i < 16; i++){
      buf1[3] += left_bits[i] * mult;
      mult = mult >>1;
    }

    // irasom zodyno dydi i buferi
    buf1[4] = 0;
    buf1[5] = 0;

    int size_of_dict = 0;
    current_node = init_node;
    while(current_node->next != NULL){
      size_of_dict++;
      current_node = current_node->next;
    }

    size_of_dict--;
    unsigned char mask = 1;
    for(i = 0; i < 8; i++){
      buf1[5] += mask & size_of_dict;
      mask = mask << 1;
    }

    mask = 1;
    size_of_dict = size_of_dict >> 8;
    for(i = 0; i < 8; i++){
      buf1[4] += mask & size_of_dict;
      mask = mask << 1;
    }
    size_of_dict++;
    
    // irasom buferi i output faila:
    fwrite(buf1, sizeof(buf1), 1, output_file);

    // irasom zodyna i output faila:
    current_buffer_bit_in_byte = 0;
    current_buffer_byte = 0;
    mult = 128;

    current_node = init_node;

    for(i = 0; i < BUFFER_SIZE; i++){
      buffer[i] = 0;
    }

    int dict_size = 0;
    
    while(current_node->next != NULL){
      for(i = 0; i < bit_number; i++){
	buffer[current_buffer_byte] += current_node->binary_representation[i] * mult;
	current_buffer_bit_in_byte++;
	mult = mult >> 1;
	if(current_buffer_bit_in_byte == 8){
	  current_buffer_byte++;
	  current_buffer_bit_in_byte = 0;
	  mult = 128;
	}
	if(current_buffer_byte == BUFFER_SIZE){
	  // pripildem buferi; metas irasyt ji i faila
	  current_buffer_bit_in_byte = 0;
	  current_buffer_byte = 0;
	  mult = 128;
	  fwrite(buffer, sizeof(buffer), 1, output_file);
	  for(int j = 0; j < BUFFER_SIZE; j++){
	    buffer[j] = 0;
	  }
	}
      }

      current_node = current_node->next;
      dict_size++;
    }

    // irasem zodyna su "dideliu" buferiu - galejo likti neirasytu bitu
    // tikrinam, ar tokiu yra, ir irasom i faila:
    int new_buf_size;
    if(current_buffer_byte > 0 || current_buffer_bit_in_byte > 0){
      if(current_buffer_bit_in_byte > 0){
	new_buf_size = current_buffer_byte + 1;
      } else {
	new_buf_size = current_buffer_byte;
      }
      unsigned char buf2[new_buf_size];
      for(i = 0; i < new_buf_size; i++){
	buf2[i] = buffer[i];
      }
      fwrite(buf2, sizeof(buf2), 1, output_file);
    }

    // pilnai irasem zodyna!

    // kadangi kodas yra modifikuotas, tai zinodami zodyno dydi, galime rasti ir visus reikalingus kodus. Sudedame visus galimus kodus i masyva:
        
    int *all_codes[dict_size];
    
    for(i = 0; i < dict_size; i++){
      all_codes[i] = malloc(CODE_ARR_LENGTH * sizeof(int));
    }
    
    if(strcmp(argv[2], "c1") == 0){
      for(i = 0; i < dict_size; i++){
	get_c1_code(i, all_codes[i]);
      }
    } else {
      for(i = 0; i < dict_size; i++){
	get_c2_code(i, all_codes[i]);
      }
    }
    
    // pradesim teksto uzkodavima ir irasinejima i rezultatu faila.
    // is naujo skaitysim input faila.

    rewind(input_file);
    Symbol *read_symbol = malloc(sizeof(Symbol));
    bits_left_in_buffer = 0;
    current_buffer_byte = 0;
    current_buffer_bit_in_byte = 0;
    left_bits_number = 0;

    
    int current_write_buffer_byte = 0;
    int current_write_buffer_bit_in_byte = 0;

    int last_seen_index[dict_size];
    for(i = 0; i < dict_size; i++){
      last_seen_index[i] = i;
    }
    
    unsigned char write_buffer[BUFFER_SIZE];    // naujas buferis - kadangi skaitom ir rasom vienu metu, negalima naudoti to pacio
    
    // isvalom abu buferius
    for(int j = 0; j < BUFFER_SIZE; j++){
      buffer[j] = 0;
      write_buffer[j] = 0;
    }

    current_buffer_bit_in_byte = 0;
    current_buffer_byte = 0;
    mult = 128;
    
    int current_symbol = dict_size;   // einamasis simbolis skaitant simbolius is failo; laikoma, kad zodynas yra pridetas failo pradzioje

    while(1){
      result = read_symbol_from_input(bit_number, input_file, read_symbol, buffer, &bits_left_in_buffer,
				      &current_buffer_byte, &current_buffer_bit_in_byte, left_bits, &left_bits_number);
      if(result != 1){
	break;
      }
      
      // kodo radimas nuskaitytam simboliui
      int current_nodes_number = 0;
      Symbol *node_to_compare = init_node;
      while(node_to_compare->next != NULL){
	int equal_bits = 0;
        for(i = 0; i < bit_number; i++){
          if(read_symbol->binary_representation[i] == node_to_compare->binary_representation[i]){
            equal_bits++;
          }
        }
	if(equal_bits == bit_number){
	  int this_symbol_last_seen = last_seen_index[current_nodes_number];
	  int distance = 0;
	  for(i = 0; i < dict_size; i++){
	    if(last_seen_index[i] > this_symbol_last_seen){
	      distance++;
	    }
	  }
	  last_seen_index[current_nodes_number] = current_symbol;
	  
	  // randam koda pagal distance ir irasom ji i buferi
	  int *current_code = malloc(CODE_ARR_LENGTH * sizeof(int));

	  for(i = 0; i <= all_codes[distance][0]; i++){
	    current_code[i] = all_codes[distance][i];
	  }
	  
	  for(i = 1; i <= current_code[0]; i++){
	    write_buffer[current_write_buffer_byte] += current_code[i] * mult;
	    current_write_buffer_bit_in_byte++;
	    mult = mult >> 1;
	    if(current_write_buffer_bit_in_byte == 8){
	      current_write_buffer_byte++;
	      current_write_buffer_bit_in_byte = 0;
	      mult = 128;
	    }
	    if(current_write_buffer_byte == BUFFER_SIZE){
	      // pripildem buferi; metas irasyt ji i faila
	      current_write_buffer_bit_in_byte = 0;
	      current_write_buffer_byte = 0;
	      mult = 128;
	      fwrite(write_buffer, sizeof(buffer), 1, output_file);
	      for(int j = 0; j < BUFFER_SIZE; j++){
		write_buffer[j] = 0;
	      }
	    } 
	  }	  
	  break;
	}
	node_to_compare = node_to_compare->next;
	current_nodes_number++;
      }
      current_symbol++;
    }    
    
    // galejo likti neirasytu bitu, jei "didelis" buferis nebuvo uzpildytas; jei tokiu liko, irasom juos i rezultatu faila su mazesniu buferiu:    
    if(current_write_buffer_byte > 0 || current_write_buffer_bit_in_byte > 0){
      if(current_write_buffer_bit_in_byte > 0){
	new_buf_size = current_write_buffer_byte + 1;
      } else {
	new_buf_size = current_write_buffer_byte;
      }
      unsigned char buf3[new_buf_size];
      for(i = 0; i < new_buf_size; i++){
	buf3[i] = write_buffer[i];
      }
      fwrite(buf3, sizeof(buf3), 1, output_file);
    }

    fclose(input_file);
    fclose(output_file);

    // paleidziam atminti
    for(i = 0; i < dict_size; i++){
      free(all_codes[i]);
    }
    free(read_symbol);
    return 0;
}

// Visu skirtingu simboliu radimo input faile funkcija. Algoritmas abstrakciau parodytas pseudo.txt faile
int read_symbol_from_input(int bit_number, FILE *input_file, Symbol *symbol, unsigned char buffer[BUFFER_SIZE], int *bits_left_in_buffer,
			   int *current_buffer_byte, int *current_buffer_bit_in_byte, int left_bits[16], int *left_bits_number){
  int i;
  // bL + bBuf >= bN
  if(*left_bits_number + *bits_left_in_buffer >= bit_number){
    for(i = 0; i < *left_bits_number; i++){
      symbol->binary_representation[i] = left_bits[i];
    }
    unsigned char mask = get_mask(*current_buffer_bit_in_byte);
    for(i = *left_bits_number; i < bit_number; i++){
      symbol->binary_representation[i] = buffer[*current_buffer_byte] & mask;
      if(*current_buffer_bit_in_byte == 7){
        *current_buffer_bit_in_byte = 0;
        (*current_buffer_byte)++;
        mask = 128;
      } else {
        (*current_buffer_bit_in_byte)++;
        mask = mask >> 1;
      }
    }
    *bits_left_in_buffer = *bits_left_in_buffer - (bit_number - *left_bits_number);
    *left_bits_number = 0;
    for(i = 0; i < bit_number; i++){
      if(symbol->binary_representation[i] > 0){
	symbol->binary_representation[i] = 1;
      } else {
	symbol->binary_representation[i] = 0;
      }
    }
    return 1;
    // bL + bBuf < bN  
  } else {
    unsigned char mask = get_mask(*current_buffer_bit_in_byte);
    for(i = 0; i < *bits_left_in_buffer; i++){
      left_bits[i + *left_bits_number] = buffer[*current_buffer_byte] & mask;
      if(*current_buffer_bit_in_byte == 7){
        *current_buffer_bit_in_byte = 0;
        (*current_buffer_byte)++;
        mask = 128;
      } else {
        (*current_buffer_bit_in_byte)++;
        mask = mask >> 1;
      }
    }
    *left_bits_number += *bits_left_in_buffer;
    int n = fread(buffer, 1, BUFFER_SIZE, input_file);
    *bits_left_in_buffer = n * 8;
    *current_buffer_byte = 0;
    *current_buffer_bit_in_byte = 0;
    // bL + bBuf >= bN
    if(*left_bits_number + *bits_left_in_buffer >= bit_number){	
      for(i = 0; i < *left_bits_number; i++){
        symbol->binary_representation[i] = left_bits[i];
      }
      unsigned char mask = get_mask(*current_buffer_bit_in_byte);
      for(i = *left_bits_number; i < bit_number; i++){
        symbol->binary_representation[i] = buffer[*current_buffer_byte] & mask;
        if(*current_buffer_bit_in_byte == 7){
          *current_buffer_bit_in_byte = 0;
          (*current_buffer_byte)++;
          mask = 128;
        } else {
          (*current_buffer_bit_in_byte)++;
          mask = mask >> 1;
        }
      }
      *bits_left_in_buffer = *bits_left_in_buffer - (bit_number - *left_bits_number);
      *left_bits_number = 0;
      for(i = 0; i < bit_number; i++){
	if(symbol->binary_representation[i] > 0){
	  symbol->binary_representation[i] = 1;
	} else {
	  symbol->binary_representation[i] = 0;
	}
      }
      return 1;
      // bl + bBuf < bN
    } else {
      for(i = 0; i < *left_bits_number; i++){
        symbol->binary_representation[i] = left_bits[i];
      }
      unsigned char mask = get_mask(*current_buffer_bit_in_byte);
      for(i = *left_bits_number; i < bit_number; i++){
        if(i < *left_bits_number + *bits_left_in_buffer){
          symbol->binary_representation[i] = buffer[*current_buffer_byte] & mask;
          if(*current_buffer_bit_in_byte == 7){
            *current_buffer_bit_in_byte = 0;
            (*current_buffer_byte)++;
            mask = 128;
          } else {
            (*current_buffer_bit_in_byte)++;
            mask = mask >> 1;
          }
        } else {
          symbol->binary_representation[i] = 0;
        }
      }
      for(i = 0; i < bit_number; i++){
	if(symbol->binary_representation[i] > 0){
	  symbol->binary_representation[i] = 1;
	} else {
	  symbol->binary_representation[i] = 0;
	}
      }
      return -1 * (*left_bits_number + *bits_left_in_buffer);
    }
  }
}


// nulinis elementas - masyvo dydis - iskaitant ir nulini elementa (t.y. kodo ilgis + 1)
void get_c1_code(int k, int arr[CODE_ARR_LENGTH]){
  int zeros_length = get_log_infimum(k);
  arr[0] = 1 + 2 * zeros_length;
  int i;
  // uzpildom pradzia nuliais
  for(i = 1; i <= zeros_length; i++){
    arr[i] = 0;
  }
  // pridedam k + 1 binarini koda
  k++;
  int binary_number_reversed[zeros_length + 1];
  unsigned char mask = 1;
  for(i = 0; i < zeros_length + 1; i++){
    binary_number_reversed[i] = mask & k;
    k = k >> 1;
  }
  int j = zeros_length;
  
  for(i = zeros_length + 1; i < 2 * (zeros_length + 1); i++){
    arr[i] = binary_number_reversed[j];
    j--;
  }
}

// nulinis elementas - masyvo dydis - iskaitant ir nulini elementa (t.y. kodo ilgis + 1)
void get_c2_code(int k, int arr[CODE_ARR_LENGTH]){
  int log = get_log_infimum(k);
  arr[0] = 2 + log + 2 * (get_log_infimum(log));
  int *c1_code = malloc(CODE_ARR_LENGTH * sizeof(int));
  get_c1_code(log, c1_code);
  int i;
  for(i = 1; i <= c1_code[0]; i++){
    arr[i] = c1_code[i];
  }
  
  k++;
  int binary_number_reversed[log + 1];
  unsigned char mask = 1;
  for(i = 0; i < log + 1; i++){
    binary_number_reversed[i] = mask & k;
    k = k >> 1;
  }
  int j = log;
  for(i = c1_code[0] + 1; i <= arr[0]; i++){
    arr[i] = binary_number_reversed[j];
    j--;
  }
  free(c1_code);
}

int get_log_infimum(int k){
  int result = 0;
  while(1){
    int one = 1;
    for(int i = 0; i < result; i++){
      one = one * 2;
    }
    if(one == k + 1){
      break;
    } else if(one > k + 1){
      result--;
      break;
    }
    result++;
  }
  return result;
}

unsigned char get_mask(int current_bit){
  unsigned char mask = 128;
  for(int i = 0; i <= current_bit; i++){
    if(i == current_bit){
      return mask;
    } else {
      mask = mask >> 1;
    }
  }
}
