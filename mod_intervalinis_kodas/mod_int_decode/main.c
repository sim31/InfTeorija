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

int get_log_infimum(int k);
void get_c1_code(int k, int arr[CODE_ARR_LENGTH]);
void get_c2_code(int k, int arr[CODE_ARR_LENGTH]);
void write_symbol(Symbol *symbol_to_write, unsigned char write_buffer[BUFFER_SIZE], FILE *output_file, int bit_number, int *current_write_buffer_byte, int *current_write_buffer_bit_in_byte);
int get_symbol(Symbol *symbol_to_get, unsigned char read_buffer[BUFFER_SIZE], FILE *input_file, int bit_number, int *current_buffer_byte, int *current_buffer_bit_in_byte, int *all_c1_codes[], int last_seen_index[], int dict_size, int *bits_left_in_buffer, int coding, int *current_symbol, Symbol *init_node);

int main(int argc, char *argv[])
{

  if(argc != 2 && argc!= 3){
      printf("\n\tBlogas argumentu kiekis.\n\tKreipinys i programa:\n\n");
      printf("\tmod_int_decode.exe <ivesties failas> [isvesties failas]\n\n");
      printf("\tIvesties failo ieskoma tame paciame kataloge, kaip ir si programa, jei nurodytas adresas nera absoliutus.\n");
      printf("\tJei isvesties failas nenurodytas, jis sukuriamas su generiniu pavadinimu\n");
      printf("\t\"decoded.txt\" tame paciame kataloge, kur ir ivesties failas.\n");
      printf("\tJei isvesties failo pavadinimas nurodytas, tai jis sukuriamas\n");
      printf("\ttame paciame kataloge, kaip ir ivesties failas, bet su nurodytu pavadinimu.\n");
      printf("\n\tPavyzdys su absoliuciu adresu:");
      printf("\n\tmod_int_decode.exe C:\\encoded.bin decoded.txt\n");
      printf("\n\tPavyzdys be absoliutaus adreso:");
      printf("\n\tmod_int_decode.exe encoded.bin decoded.txt\n");
      return -1;
  }

  // input failo pavadinimo tikrinimas
    int i = 0;
    int input_file_has_abs_path = 0;
    while(argv[1][i] != '\0'){
        #ifdef WINDOWS
        if(argv[1][i] == '\\'){
            input_file_has_abs_path = 1;
        }
        #else
        if(argv[1][i] == '/'){
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
        while(argv[1][i] != '\0'){
            input_file_name[string_end_index] = argv[1][i];
            i++;
            string_end_index++;
        }
        input_file_name[string_end_index] = '\0';
    } else {
        // jei input failas turi absoliutu kelia
        int i = 0;
        while(argv[1][i] != '\0'){
            input_file_name[i] = argv[1][i];
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
        if(argc == 2){
            #ifdef WINDOWS
            output_file_name[last_folder_index] = '\\';
            #else
            output_file_name[last_folder_index] = '/';
            #endif // WINDOWS
            last_folder_index++;
            output_file_name[last_folder_index] = 'd';
            output_file_name[last_folder_index + 1] = 'e';
            output_file_name[last_folder_index + 2] = 'c';
            output_file_name[last_folder_index + 3] = 'o';
            output_file_name[last_folder_index + 4] = 'd';
            output_file_name[last_folder_index + 5] = 'e';
            output_file_name[last_folder_index + 6] = 'd';
            output_file_name[last_folder_index + 7] = '.';
            output_file_name[last_folder_index + 8] = 't';
            output_file_name[last_folder_index + 9] = 'x';
            output_file_name[last_folder_index + 10] = 't';
            output_file_name[last_folder_index + 11] = '\0';
        } else {
            #ifdef WINDOWS
            output_file_name[last_folder_index] = '\\';
            #else
            output_file_name[last_folder_index] = '/';
            #endif // WINDOWS
            last_folder_index++;
            int i = 0;
            while(argv[2][i] != '\0'){
                output_file_name[last_folder_index] = argv[2][i];
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
        if(argc == 3){
            while(argv[1][i] != '\0'){
            output_file_name[string_end_index] = argv[2][i];
            i++;
            string_end_index++;
            }
            output_file_name[string_end_index] = '\0';
        } else {
            output_file_name[string_end_index] = 'd';
            output_file_name[string_end_index + 1] = 'e';
            output_file_name[string_end_index + 2] = 'c';
            output_file_name[string_end_index + 3] = 'o';
            output_file_name[string_end_index + 4] = 'd';
            output_file_name[string_end_index + 5] = 'e';
            output_file_name[string_end_index + 6] = 'd';	    
            output_file_name[string_end_index + 7] = '.';
            output_file_name[string_end_index + 8] = 't';
            output_file_name[string_end_index + 9] = 'x';
            output_file_name[string_end_index + 10] = 't';
            output_file_name[string_end_index + 11] = '\0';
        }
    }

    // sukuriam output faila:
    FILE *output_file;
    output_file = fopen(output_file_name, "w");

    // Susitvarkem su pradiniais failais ir vartotojo inputu.

    // Skaitom pirmus 6 baitus, t.y. antraste:

    // 1 baitas - pirmi 4 bitai is kaires - bitu kiekis simbolyje (skaiciuojama nuo nulio - 0 reiskia 1 bita, 1 - 2 bitus ir t.t.), paskutinis bitas - koduote (c1 - 0 arba c2 - 1)
    // 1 baitas - netilpusiu bitu kiekis (0 - 15)
    // 2 baitai - netilpe bitai (trukstamos vietos is galo uzpildomos nuliais)
    // 2 baitai - zodyno dydis (skaiciuojama nuo nulio - 0 reiskia 1 simboli zodyne, 1 - 2 simbolius ir t.t.)
    // zodynas ...
    // uzkoduoti simboliai ...

    unsigned char header_buffer[6];
    int n = fread(header_buffer, 1, 6, input_file);

    // nusistatom koduote
    int coding;
    if(header_buffer[0] == (header_buffer[0] >> 1) << 1){
      coding = 0;  // c1 koduote
    } else {
      coding = 1;  // c2 koduote
    }

    // nusistatom zodzio bitu skaiciu
    int bit_number;
    header_buffer[0] = header_buffer[0] >> 4;
    bit_number = header_buffer[0] + 1;

    // nusiskaitom netilpusiu bitu kieki
    int left_bits_number = header_buffer[1];

    // netilpe bitai - header_buffer[2] ir header_buffer[3] baituose; panaudosim veliau

    // nusiskaitom zodyno dydi:
    int dict_size = 256 * header_buffer[4] + header_buffer[5] + 1;

    // nusistatom, kiek baitu uzima zodynas input faile ir ji nusiskaitome
    int dict_bytes_num = bit_number * dict_size;
    if(dict_bytes_num != (dict_bytes_num / 8) * 8){
      dict_bytes_num = dict_bytes_num / 8 + 1;
    } else {
      dict_bytes_num = dict_bytes_num / 8;
    }
    unsigned char dict_buffer[dict_bytes_num];
    n = fread(dict_buffer, 1, dict_bytes_num, input_file);

    // sudedame zodyno zodzius i linked lista
    Symbol *init_node = NULL;                           // rodykle i simboliu linked lista (t.y. zodyna)
    Symbol *current_node = NULL;                        // rodykle iteravimui per linked lista
    int current_buffer_byte = 0;
    int current_buffer_bit_in_byte = 0;
    
    init_node = malloc(sizeof(Symbol));
    current_node = init_node;
    for(i = 0; i < dict_size; i++){
      current_node->next = malloc(sizeof(Symbol));
      current_node = current_node->next;
    }
    current_node = NULL;

    int mask = 128;
    current_node = init_node;
    while(current_node->next != NULL){
      for(i = 0; i < bit_number; i++){
	if(dict_buffer[current_buffer_byte] & mask){
	  current_node->binary_representation[i] = 1;
	} else {
	  current_node->binary_representation[i] = 0;
	}
	current_buffer_bit_in_byte++;
	if(current_buffer_bit_in_byte == 8){
	  current_buffer_byte++;
	  current_buffer_bit_in_byte = 0;
	} else {
	  dict_buffer[current_buffer_byte] = dict_buffer[current_buffer_byte] << 1;
	}
      }
      current_node = current_node->next;
    }

    // kadangi intervalinis kodas modifikuotas, pagal zodyno dydi iskart galime nusistatyti visus galimus kodus:

    int *all_c1_codes[dict_size];
    
    for(i = 0; i < dict_size; i++){
      all_c1_codes[i] = malloc(CODE_ARR_LENGTH * sizeof(int));
    }
    // irasom c1 kodus i masyva! jei koduote bus c2, tai reikes susirasti ir ja (bet veliau)
    for(i = 0; i < dict_size; i++){
      get_c1_code(i, all_c1_codes[i]);
    }

    // susitvarkem su antrastem ir zodynu; pradesim kodu skaityma ir dekodavima

    // pagalbiniai kintamieji
    current_buffer_byte = 0;
    current_buffer_bit_in_byte = 0;
    
    int current_write_buffer_byte = 0;
    int current_write_buffer_bit_in_byte = 0;
    
    unsigned char read_buffer[BUFFER_SIZE];
    unsigned char write_buffer[BUFFER_SIZE];
    for(i = 0; i < BUFFER_SIZE; i++){
      read_buffer[i] = 0;
      write_buffer[i] = 0;
    }

    // fiktyviai pridedam zodyna
    int last_seen_index[dict_size];
    for(i = 0; i < dict_size; i++){
      last_seen_index[i] = i;
    }

    int current_symbol = dict_size;
    int bits_left_in_buffer = 0;

    Symbol *found_symbol;
    
    while(1){
      found_symbol = malloc(sizeof(Symbol));
      int result = get_symbol(found_symbol, read_buffer, input_file, bit_number, &current_buffer_byte, &current_buffer_bit_in_byte, all_c1_codes, last_seen_index, dict_size, &bits_left_in_buffer, coding, &current_symbol, init_node);
      if(result == -1){
	break;
      }
      write_symbol(found_symbol, write_buffer, output_file, bit_number, &current_write_buffer_byte, &current_write_buffer_bit_in_byte);
      free(found_symbol);
    }
    
    // galejo likti neirasytu bitu rasymo buferyj arba gali buti atlikusiu bitu simboliu uzkodavimo metu (left_bits - buvo pateikti failo antrasteje).
    if(left_bits_number || current_write_buffer_bit_in_byte || current_write_buffer_byte){
      int leftovers_buffer_size;
      if(left_bits_number + current_write_buffer_bit_in_byte > 8){
	leftovers_buffer_size = current_write_buffer_byte + 2;
      } else if(left_bits_number + current_write_buffer_bit_in_byte > 0){
	leftovers_buffer_size = current_write_buffer_byte + 1;
      } else {
	leftovers_buffer_size = current_write_buffer_byte;
      }
      unsigned char leftovers_buffer[leftovers_buffer_size];
      
      // pirma irasom write buferyj likusius bitus
      int rewrite_bytes_number;
      if(current_write_buffer_bit_in_byte > 0){
	rewrite_bytes_number = current_write_buffer_byte + 1;
      } else {
	rewrite_bytes_number = current_write_buffer_byte;
      }	      
      for(i = 0; i < rewrite_bytes_number; i++){
	leftovers_buffer[i] = write_buffer[i];
      }
      
      // ir irasom left_bits i nauja write buferi:
      if(left_bits_number > 0){
	int left_bits_mask = 128;
	int mult = 128 >> (current_write_buffer_bit_in_byte);
	unsigned char *left_bits_byte = &header_buffer[2];
	for(i = 0; i < left_bits_number; i++){
	  // pereinam i kita left_bits baita, jei pirmas baigesi
	  if(i == 8){
	    left_bits_byte = &header_buffer[3];
	    left_bits_mask = 128;
	  }
	  // nuskaitom bita is left_bits
	  int current_left_bit = left_bits_mask & *left_bits_byte;
	  if(current_left_bit > 0){
	    current_left_bit = 1;
	  }
	  left_bits_mask = left_bits_mask >> 1;
	  // ir irasom i buferi
	  leftovers_buffer[current_write_buffer_byte] += current_left_bit * mult;
	  current_write_buffer_bit_in_byte++;
	  if(current_write_buffer_bit_in_byte == 8){
	    current_write_buffer_bit_in_byte = 0;
	    current_write_buffer_byte++;
	    mult = 128;
	  } else {
	    mult = mult >> 1;
	  }	  
	}
      }

      // perkeliam viska i char buferi ir irasom i faila
      char char_buffer[leftovers_buffer_size];
      for(i = 0; i < leftovers_buffer_size; i++){
	char_buffer[i] = (char)(leftovers_buffer[i]);
      }
      fwrite(char_buffer, leftovers_buffer_size, 1, output_file);    
    }
    
    fclose(input_file);
    fclose(output_file);
  
    return 0;
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

// rasymo f-ja. Pateikto simbolio bitai kaupiami buferyje, ir jei buferis uzpildytas - jis irasomas i faila
void write_symbol(Symbol *symbol_to_write, unsigned char write_buffer[BUFFER_SIZE], FILE *output_file, int bit_number, int *current_write_buffer_byte, int *current_write_buffer_bit_in_byte){
  for(int i = 0; i < bit_number; i++){
    int mult = 128 >> (*current_write_buffer_bit_in_byte);
    if(symbol_to_write->binary_representation[i]){
      write_buffer[*current_write_buffer_byte] += mult;
    }
    (*current_write_buffer_bit_in_byte)++;
    if(*current_write_buffer_bit_in_byte == 8){
      *current_write_buffer_bit_in_byte = 0;
      (*current_write_buffer_byte)++;
      if(*current_write_buffer_byte == BUFFER_SIZE){
	char char_buffer[BUFFER_SIZE];
	for(int j = 0; j < BUFFER_SIZE; j++){
	  char_buffer[j] = (char)(write_buffer[j]);
	}
	fwrite(char_buffer, BUFFER_SIZE, 1, output_file);
	for(int j = 0; j < BUFFER_SIZE; j++){
	  write_buffer[j] = 0;
	}
	*current_write_buffer_bit_in_byte = 0;
	*current_write_buffer_byte = 0;
      }
    }
  }
}

int get_symbol(Symbol *symbol_to_get, unsigned char read_buffer[BUFFER_SIZE], FILE *input_file, int bit_number,
	       int *current_buffer_byte, int *current_buffer_bit_in_byte, int *all_c1_codes[], int last_seen_index[], int dict_size, int *bits_left_in_buffer, int coding, int *current_symbol, Symbol *init_node){
  // ieskom kodo buferyj
  int *found_code = malloc(CODE_ARR_LENGTH * sizeof(int));

  int mask = 128 >> (*current_buffer_bit_in_byte);
  
  int zeros_length = 0;
  // ieskom nuliu
  while(1){
    if(*bits_left_in_buffer == 0){
      int n = fread(read_buffer, 1, BUFFER_SIZE, input_file);
      if(n == 0){
	free(found_code);
	return -1;
      }
      *current_buffer_byte = 0;
      *current_buffer_bit_in_byte = 0;
      *bits_left_in_buffer = n * 8;
      mask = 128;
    } else {
      if((mask & read_buffer[*current_buffer_byte]) == 0){
	zeros_length++;
	(*bits_left_in_buffer)--;
	(*current_buffer_bit_in_byte)++;
	if(*current_buffer_bit_in_byte == 8){
	  (*current_buffer_byte)++;
	  *current_buffer_bit_in_byte = 0;
	  mask = 128;
	} else {
	  mask = mask >> 1;
	}
      } else {
	break;
      }
    }
    
  }
  // suformuojam galimo kodo ilgi:
  found_code[0] = 2 * zeros_length + 1;
  for(int i = 1; i <= zeros_length; i++){
    found_code[i] = 0;
  }
  
  // nuskaitom likusius bitus galimam kodui
  for(int i = zeros_length + 1; i <= 2 * zeros_length + 1; i++){
    if(*bits_left_in_buffer == 0){
      int n = fread(read_buffer, 1, BUFFER_SIZE, input_file);
      if(n == 0){
	free(found_code);
	return -1;
      }
      *current_buffer_byte = 0;
      *current_buffer_bit_in_byte = 0;
      *bits_left_in_buffer = n * 8;
      mask = 128;
    }
    found_code[i] = mask & read_buffer[*current_buffer_byte];
    (*bits_left_in_buffer)--;
    (*current_buffer_bit_in_byte)++;
    if(*current_buffer_bit_in_byte == 8){
      (*current_buffer_byte)++;
      (*current_buffer_bit_in_byte) = 0;
      mask = 128;
    } else {
      mask = mask >> 1;
    }
  }
  
  for(int i = 1; i <= found_code[0]; i++){
    if(found_code[i]){
      found_code[i] = 1;
    }
  }
  
  // bandom ieskoti suformuoto kodo visu galimu kodu masyve:
  int distance = -1;
  int equal_bits;
  for(int i = 0; i < dict_size; i++){
    if(found_code[0] > all_c1_codes[i][0]){
      continue;
    }
    if(found_code[0] < all_c1_codes[i][0]){
      break;
    }
    equal_bits = 0;
    for(int j = 1; j <= all_c1_codes[i][0]; j++){
      if(all_c1_codes[i][j] == found_code[j]){
	equal_bits++;
      }
    }
    if(equal_bits == found_code[0]){
      distance = i;
    }
  }
  if(distance < 0){
    free(found_code);
    return -1;
  }

  // jei koduote buvo c1, tai jau radom distancija; jei koduote yra c2, reikia papildomu veiksmu:
  if(coding == 1){

    // zinodami c1 kodo parametra k, galime nusistatyti c2 kodo ilgi:
    int code_length = 2 + distance + 2 * get_log_infimum(distance);

    // nuskaitom trukstamus bitus:

    for(int i = found_code[0] + 1; i <= code_length; i++){
      if(*bits_left_in_buffer == 0){
	int n = fread(read_buffer, 1, BUFFER_SIZE, input_file);
	if(n == 0){
	  free(found_code);
	  return -1;
	}
	*current_buffer_byte = 0;
	*current_buffer_bit_in_byte = 0;
	*bits_left_in_buffer = n * 8;
	mask = 128;
      }
      found_code[i] = mask & read_buffer[*current_buffer_byte];
      (*bits_left_in_buffer)--;
      (*current_buffer_bit_in_byte)++;
      if(*current_buffer_bit_in_byte == 8){
	(*current_buffer_byte)++;
	(*current_buffer_bit_in_byte) = 0;
	mask = 128;
      } else {
	mask = mask >> 1;
      }
    }
  
    for(int i = 1; i <= code_length; i++){
      if(found_code[i]){
	found_code[i] = 1;
      }
    }

    found_code[0] = code_length;
    
    // suformavom c2 koda; reikia susidaryti visu galimu c2 kodu masyva ir surasti tikraja distancija
    
    int *all_c2_codes[dict_size];
    int i;
    
    for(i = 0; i < dict_size; i++){
      all_c2_codes[i] = malloc(CODE_ARR_LENGTH * sizeof(int));
    }
    // irasom c2 kodus i masyva
    for(i = 0; i < dict_size; i++){
      get_c2_code(i, all_c2_codes[i]);
    }

    // ir surandam tikraja (c2) distancija
    
    for(i = 0; i < dict_size; i++){
      if(found_code[0] > all_c2_codes[i][0]){
	continue;
      }
      if(found_code[0] < all_c2_codes[i][0]){
	break;
      }
      equal_bits = 0;
      for(int j = 1; j <= all_c2_codes[i][0]; j++){
	if(all_c2_codes[i][j] == found_code[j]){
	  equal_bits++;
	}
      }
      if(equal_bits == found_code[0]){
	distance = i;
      }
    } 
  }
  
  // radom distancija; ieskome pradinio simbolio, kuris buvo uzkoduotas
  // algoritmas:
  // ieskosim veliausiai pasirodziusio tekste simbolio tiek kartu, kiek yra distancija, juos atmesdami.
  // tada vel rasim veliausiai pasirodziusi simboli - tai ir bus ieskomas simbolis.
  
  int temp_seen_index[dict_size];
  for(int i = 0; i < dict_size; i++){
    temp_seen_index[i] = last_seen_index[i];
  }
  
  // atmetam simbolius pagal distancija
  int max;
  for(int i = 0; i < distance; i++){
    max = -1;
    // ieskom maksimumo
    for(int j = 0; j < dict_size; j++){
      if(temp_seen_index[j] > max){
	max = temp_seen_index[j];
      }
    }
    for(int j = 0; j < dict_size; j++){
      if(temp_seen_index[j] == max){
	temp_seen_index[j] = -1;
      }
    }
  }
  
  int symbol_number;
  // ir randam tikrojo simbolio eiles nr. zodyne (vel ieskom maksimumo):
  max = -1;
  for(int i = 0; i < dict_size; i++){
    if(temp_seen_index[i] > max){
      max = temp_seen_index[i];
    }
  }
  for(int i = 0; i < dict_size; i++){
    if(temp_seen_index[i] == max){
      symbol_number = i;
      last_seen_index[i] = *current_symbol;
    }      
  }
  (*current_symbol)++;
  
  // radom simbolio indeksa zodyne! dabar reikia suformuoti pati simboli:
  Symbol *temp_symbol = init_node;
  for(int i = 0; i < symbol_number; i++){
    temp_symbol = temp_symbol->next;
  }
  for(int i = 0; i < bit_number; i++){
    symbol_to_get->binary_representation[i] = temp_symbol->binary_representation[i];
  }
  free(found_code);
  return 0;
}
