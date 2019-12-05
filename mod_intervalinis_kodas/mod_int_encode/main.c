#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define WINDOWS // uzkomentuot linuxams
#ifdef WINDOWS
#include <direct.h>
#define GetCurrentDir _getcwd
#else
#include <unistd.h>
#define GetCurrentDir getcwd
#endif

#define BUFFER_SIZE 8

typedef struct symbol
{
    int binary_representation[16];              // bitai tokie, kaip nuskaityti is buferio
    int last_seen_index;                        // paskutio pasirodymo tekste indeksas
} Symbol;

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
    if (bit_number > 12 || bit_number < 1){
        printf("\n\n\tBlogas bitu skaicius. Bitu skaicius turi buti intervale nuo 1 iki 12 imtinai\n");
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
        fclose(input_file);
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
            output_file_name[last_folder_index + 7] = 't';
            output_file_name[last_folder_index + 8] = 'x';
            output_file_name[last_folder_index + 9] = 't';
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
            output_file_name[string_end_index + 7] = 't';
            output_file_name[string_end_index + 8] = 'x';
            output_file_name[string_end_index + 9] = 't';
            output_file_name[string_end_index + 10] = '\0';
        }
    }

    // sukuriam output faila:
    FILE *output_file;
    output_file = fopen(output_file_name, "rb");

    // skaitom input faila:

    int read_symbol[bit_number];                        // zodyno zodzio binarine reprezentacija; ilgis priklauso nuo pasirinkto bitu skaiciaus
    int bits_needed_for_symbol = bit_number;            // kiek dar reikia paimti bitu is buferio, kad pilnai sudarytume simboli?

    int n;                                              // kiek baitu buvo nuskaityta i buferi
    unsigned char buffer[BUFFER_SIZE];                  // buferis - jame laikoma nuskaitytas inputas
    int current_byte;                                   // einamasis buferio baitas, is kurio imame bitus
    int bits_left_in_byte;                              // kiek bitu liko einamajame baite dar nepaimtu

    while(!feof(input_file)){
        n = fread(buffer, 1, BUFFER_SIZE, input_file);
        bits_left_in_byte = 8;
        current_byte = 0;

    }

    fclose(input_file);
    fclose(output_file);
    return 0;
}

int* get_c1_code(int k){
    int* a;
    return a;
}

int* get_c2_code(int k){

}
