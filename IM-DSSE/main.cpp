#include "Client_DSSE.h"
#include "DSSE.h"
#include "config.h"
#include "Miscellaneous.h"
#include <fstream>
#include <map>
#include <vector>
#include <string>
#include <algorithm>
#include <limits>
#include <dirent.h>
#include <sys/stat.h>

using namespace std;

std::map<TYPE_INDEX, std::string> reverse_file_map;

void printMenu();

bool fexists(string filename_with_path)
{
    ifstream ifile(filename_with_path.c_str());
    return ifile.good();
}

void load_reverse_map() {
    reverse_file_map.clear();
    string rev_map_path = gcsDataStructureFilepath + "reverse_map.txt";
    ifstream rev_map_file(rev_map_path.c_str());
    if(!rev_map_file.is_open()) {
        cout << "   PERINGATAN: File 'reverse_map.txt' tidak ditemukan." << endl;
        return;
    }
    TYPE_INDEX index;
    string filename;
    while(rev_map_file >> index >> filename) {
        reverse_file_map[index] = filename;
    }
    rev_map_file.close();
    cout << "   Reverse map untuk " << reverse_file_map.size() << " nama file berhasil dimuat." << endl;
}

void save_reverse_map() {
    string rev_map_path = gcsDataStructureFilepath + "reverse_map.txt";
    ofstream rev_map_file(rev_map_path.c_str());
    if (rev_map_file.is_open())
    {
        for (map<TYPE_INDEX, string>::iterator it = reverse_file_map.begin(); it != reverse_file_map.end(); ++it)
        {
            rev_map_file << it->first << " " << it->second << endl;
        }
        rev_map_file.close();
        cout << "   Reverse map berhasil disimpan." << endl;
    }
}

int main(int argc, char **argv)
{
    string seed = "123456";
#if defined(DISK_STORAGE_MODE)
    cout << "DISK STORAGE MODE" << endl;
#else
    cout << "RAM STORAGE MODE" << endl;
#endif
    cout << "# FILE:" << MAX_NUM_OF_FILES << endl;
    cout << "# KW: " << MAX_NUM_KEYWORDS << endl;
    cout << "server ID:" << PEER_ADDRESS << endl;

    auto start = time_now;
    auto end = time_now;

    setbuf(stdout, NULL);

    Client_DSSE* client_dsse = new Client_DSSE();
    string str_keyword;
    string updating_filename;
    TYPE_COUNTER search_result;

    while (1)
    {
        int selection = -1;
        printMenu();
        cout << "Select your choice: ";
        // MODIFIKASI: Ubah batas atas menjadi 6
        while (!(cin >> selection) || selection < 0 || selection > 6)
        {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Invalid input. Try again: ";
        }

        switch (selection)
        {
        case 0:
            client_dsse->loadState();
            client_dsse->sendCommandOnly(CMD_LOADSTATE);
            load_reverse_map(); 
            break;
        case 1:
            start = time_now;
            client_dsse->createEncrypted_data_structure();
            end = time_now;
            cout << "BUILDING TIME: " << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() << " ms" << endl;
            load_reverse_map(); 
            break;
        case 2:
            cout << "Keyword search: ";
            cin >> str_keyword;
            std::transform(str_keyword.begin(), str_keyword.end(), str_keyword.begin(), ::tolower);
            search_result = 0;
            start = time_now; 
            client_dsse->searchKeyword(str_keyword, search_result);
            end = time_now;
            cout << "SEARCH TIME: " << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() << " ms" << endl;
            cout << " Keyword *" << str_keyword << "* appeared in " << search_result << " files" << endl;

            if (search_result > 0)
            {
                cout << "   Matching files:" << endl;
                vector<TYPE_INDEX> lstFile_id;
                Miscellaneous misc; 
                misc.read_list_from_file(FILENAME_SEARCH_RESULT, gcsDataStructureFilepath, lstFile_id);
                for (size_t i = 0; i < lstFile_id.size(); ++i)
                {
                    TYPE_INDEX file_idx = lstFile_id[i];
                    if (reverse_file_map.count(file_idx))
                    {
                        cout << "   - " << reverse_file_map[file_idx] << endl;
                    }
                    else
                    {
                        cout << "   - [Filename not found for index: " << file_idx << "]" << endl;
                    }
                }
            }
            break;
        case 3:
            {
                cout << "Specify the filename want to add: ";
                cin >> updating_filename;
                if (!fexists(gcsUpdateFilepath + updating_filename))
                {
                    cout << endl << "File not found! Please put/check if the file exists in *data/update* folder" << endl;
                    break;
                }
                start = time_now;
                TYPE_INDEX new_idx = client_dsse->addFile(updating_filename, gcsUpdateFilepath);
                end = time_now;
                cout << "ADD TIME: " << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() << " ms" << endl;
                if (new_idx != FILE_NOT_EXIST) {
                    reverse_file_map[new_idx] = updating_filename;
                    cout << "   Reverse map diperbarui untuk file baru: " << updating_filename << " dengan indeks " << new_idx << endl;
                }
            }
            break;
        case 4:
            {
                cout << "Specify the filename want to delete: ";
                cin >> updating_filename;
                start = time_now;
                TYPE_INDEX deleted_idx = client_dsse->delFile(updating_filename, gcsUpdateFilepath);
                end = time_now;
                cout << "TOTAL UPDATE TIME: " << std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count() << " ns" << endl;
                
                if (deleted_idx != FILE_NOT_EXIST) {
                    if (reverse_file_map.count(deleted_idx)) {
                        reverse_file_map.erase(deleted_idx);
                        cout << "   Entri untuk file " << updating_filename << " (indeks " << deleted_idx << ") dihapus dari reverse map." << endl;
                    }
                }
            }
            break;
        case 5:
            client_dsse->saveState();
            save_reverse_map(); 
            client_dsse->sendCommandOnly(CMD_SAVESTATE);
            exit(0); 
            break;
        
        // MODIFIKASI: Tambahkan case baru untuk dekripsi
        case 6:
            {
                cout << "Masukkan nama file asli yang ingin didekripsi: ";
                string filename_to_decrypt;
                cin >> filename_to_decrypt;

                bool found = false;
                TYPE_INDEX file_idx_to_request = FILE_NOT_EXIST;

                // Cari indeks yang sesuai dengan nama file
                for (auto const& [idx, name] : reverse_file_map)
                {
                    if (name == filename_to_decrypt)
                    {
                        file_idx_to_request = idx;
                        found = true;
                        break;
                    }
                }

                if (found)
                {
                    client_dsse->requestAndDecryptFile(file_idx_to_request);
                }
                else
                {
                    cout << "   File dengan nama '" << filename_to_decrypt << "' tidak ditemukan dalam state saat ini." << endl;
                }
            }
            break;
        default:
            break;
        }
    }
    return 0;
}

void printMenu()
{
    cout << "\n---------------\n";
    cout << "0. Load previous state" << endl;
    cout << "1. (Re)build data structure" << endl;
    cout << "2. Keyword search: " << endl;
    cout << "3. Add files" << endl;
    cout << "4. Delete files" << endl;
    cout << "5. Save current state and Exit" << endl;
    // MODIFIKASI: Tambahkan opsi menu baru
    cout << "6. Decrypt and view a file" << endl;
    cout << "---------------\n";
}
