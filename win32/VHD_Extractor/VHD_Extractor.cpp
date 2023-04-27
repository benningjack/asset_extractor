// VHD_Extractor.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <libregf.h>
#include <vector>
#include <algorithm>
#include<set>
#include <fstream>
#include <filesystem>
#include <regex>
// Imports all necessary TSK libraries
#include "tsk/tsk_tools_i.h"
#include "tsk/libtsk.h"
#include <tsk/auto/tsk_auto.h>
#include <iostream>
#include <string>
#include <sqlite3.h>
#include <pugixml.hpp>
#include <nlohmann/json.hpp>

//Global variables used in multiple methods:
using json = nlohmann::json;
std::vector<std::string> userFiles;
int datCounter = 0;
int lvmDirectoryIndex = -1;

int readXML(const char* f) {

    //checks that file can be loaded 
    pugi::xml_document doc;
    if (!doc.load_file(f)) {
        std::cerr << "Failed to load XML file" << std::endl;
        return 1;
    }

    std::string package_name = "";
    std::string package_url = "";

    //start of tree
    pugi::xml_node metadata_node = doc.child("metadata");

    //iterate tree to get specific child nodes 

    return 0;

}
//Classifies which image type based upon the enum type that the TSK return
std::string getImageType(int type)
{
    if (type == 0x0001)
    {
        return "Raw";
    }
    else if (type == 0x0004)
    {
        return "AFF AFF";
    }
    else if (type == 0x0008)
    {
        return "AFD AFF";
    }
    else if (type == 0x0010)
    {
        return "AFM AFF";
    }
    else if (type == 0x0040)
    {
        return "EWF";
    }
    else if (type == 0x0080)
    {
        return "VMDK";
    }
    else if (type == 0x0100)
    {
        return "VHD";
    }
    else if (type == 0x4000)
    {
        return "Pool";
    }
    else if (type == 0x8000)
    {
        return "Logical Directory";
    }
    return "Undefined";
}

/*WINDOWS IMPLEMENTATION*/
/*
* This method is responsible for creating the SOFTWARE file from the windows image provided
*/
void processSoftware(TskFsFile* file)
{
    TSK_OFF_T fSize = file->getMeta()->getSize(); //Variable that represents the size of the SOFTWARE file
    char* softwareBuffer = (char*)malloc(2048); // Allocated 2048 bytes in the buffer that will be used to read the contents of the SOFTWARE.
    TSK_OFF_T off = 0;
    size_t len = 0;
    ssize_t cnt;
    int flag = 0;

    FILE* pFile; // File object that represents the file we will be creating
    //Creates a file object called extracted_SOFTWARE and gives it write binary permisions
    pFile = fopen("extracted_SOFTWARE", "wb");
    userFiles.push_back("extracted_SOFTWARE");
    fpos_t position;
    //This for loop allows our program to read the contents of the SOFTWARE file at 2048 bytes at a time into the buffer and then writes it into our newly created file.
    for (off = 0; off < fSize; off += len) {
        //Determines the length that needs to be read
        if (fSize - off < 2048)
            len = (size_t)(fSize - off);
        else
            len = 2048;
        //Transfers the contents of the actual file into the buffer
        cnt = file->read(off, softwareBuffer, len, (TSK_FS_FILE_READ_FLAG_ENUM)flag);
        //Checks to see if the file was unable to be read and returns an error message
        if (cnt == -1) {
            std::cout << "Error Reading Software Buffer!" << std::endl;
            break;
        }
        //Writes the contents of the buffer into the newly created file
        fwrite(softwareBuffer, sizeof(char), len, pFile);
    }
    //Closes the file we are writing into and the file we were analyzing
    fclose(pFile);
    file->close();
}

//This method is responsible for processing each user's DAT file and make a copy on the local machine.
void processDAT(TskFsFile* file, int counter)
{
    TSK_OFF_T fSize = file->getMeta()->getSize(); // Gets the size of the file
    char* softwareBuffer = (char*)malloc(2048); // Allocates 2048 bytes in the buffer
    //Variables used to write 2048 bytes at a time into the buffer and our newly created file
    TSK_OFF_T off = 0;
    size_t len = 0;
    ssize_t cnt;
    int flag = 0;
    //File object that we will use to create a local verion of the DAT file.
    FILE* pFile;
    std::string fileName = std::to_string(counter) + "extracted_NTUSER.DAT"; //Formulates unique string name for each DAT file found
    userFiles.push_back(fileName);
    std::cout << "Created DAT file: " << fileName << std::endl;
    const char* fileNameDAT = fileName.c_str();
    pFile = fopen(fileNameDAT, "wb"); //Creates file object using the new name generated and give it writing permissions
    fpos_t position;
    //Reads the contense of each DAT file 2048 bytes at a time
    for (off = 0; off < fSize; off += len) {
        //Checks to see if there are 2048 bytes to read. If not it adjusts the length to read to the remaining size.
        if (fSize - off < 2048)
            len = (size_t)(fSize - off);
        else
            len = 2048;
        //Reads contents of the DAT file into the software buffer
        cnt = file->read(off, softwareBuffer, len, (TSK_FS_FILE_READ_FLAG_ENUM)flag);
        // Checks to see if the file was unable to be readand returns an error message and prints error message
        if (cnt == -1) {
            fprintf(stderr, "Error reading %s file: %s\n",
                ((file->getName()->getFlags()
                    & TSK_FS_NAME_FLAG_UNALLOC)
                    || (file->getMeta()->getFlags()
                        & TSK_FS_META_FLAG_UNALLOC)) ?
                "unallocated" : "allocated",
                file->getName()->getName());
            tsk_error_print(stderr);
            break;
        }
        //Writes content from buffer into locally created file.
        fwrite(softwareBuffer, sizeof(char), len, pFile);
    }
    //Closes the file we are writing into and the file we were analyzing
    fclose(pFile);
    file->close();
}
// This method is responsible iterating through the directories of the VHD file provided and finding the desired files
// needed to formulate software list for the Windows environment

void extractDirectoryFiles(TskFsInfo* selectedFS, TSK_INUM_T volumeOffset)
{
    TskFsDir* directory = new TskFsDir();// Represents file system directory we are currently analyzing
    //Checks to see if the directory can be opened. Prints a error message if it can't
    if (directory->open(selectedFS, volumeOffset) != 0)
    {
        std::cout << "  Error opening directory!" << std::endl;
    }
    else
    {
        //Iterates through the directory to find the necessary files SOFTWARE and NTUSER.DAT files
        for (size_t i = 0; i < directory->getSize(); i++)
        {
            TskFsFile* file = directory->getFile(i);
            std::string fileName = file->getName()->getName();
            //If SOFTWARE file is found, it processes that file.
            if (file->getMeta()->getType() == TSK_FS_META_TYPE_REG && fileName == "SOFTWARE")
            {
                std::cout << "Processing SOFTWARE FILE!" << std::endl;
                processSoftware(file);
            }
            //If "NTUSER.DAT" file is found, it processes that file
            else if (file->getMeta()->getType() == TSK_FS_META_TYPE_REG && fileName == "NTUSER.DAT")
            {
                datCounter++;
                std::cout << "Processing NTUSER.DAT FILE!" << std::endl;
                processDAT(file, datCounter);
            }
        }
    }

}

//Extracts the DAT files from each user if avaliable
void findUserDATFiles(TskFsInfo* selectedFS, TSK_INUM_T volumeOffset, TSK_STACK* addressStack)
{
    TskFsDir* directory = new TskFsDir();// Represents the directory we are currently analyzing
    //Checks to see if the directory can be opened
    if (directory->open(selectedFS, volumeOffset) != 0)
    {
        //std::cout << "  Error opening directory!" << std::endl;
    }
    else
    {
        //Iterates through each user's directory (for each account user) to see if the user has a NTUSER.DAT file to be anaylzed.
        for (size_t i = 0; i < directory->getSize(); i++)
        {
            TskFsFile* file = directory->getFile(i);
            //Checks to see if it is a valid user directory
            if (file->getMeta()->getType() == TSK_FS_META_TYPE_DIR && !TSK_FS_ISDOT(file->getName()->getName()))
            {
                //Opens directory and extracts desired user file.
                extractDirectoryFiles(selectedFS, file->getMeta()->getAddr());
            }

        }
    }
}

// This method traverses through the computer image to locate path that contains the desired SOFTWARE and NTUSER.DAT files.
// It ignores all other directories that are not of interest.
void findWindowsBinary(TskFsInfo* selectedFS, TSK_INUM_T volumeOffset, TSK_STACK* addressStack)
{
    TskFsDir* directory = new TskFsDir();
    //Makes sure the current address in the file system provided is a directory type.
    if (directory->open(selectedFS, volumeOffset) != 0)
    {
        std::cout << "  Error opening directory!" << std::endl;
    }
    else
    {
        //Iterates through the directory
        for (size_t i = 0; i < directory->getSize(); i++)
        {
            //Gets item located in the directory that needs to be checked.
            TskFsFile* file = directory->getFile(i);
            if (file == NULL)
            {
                std::cout << "Could not retrieve file!" << std::endl;
            }
            else
            {
                //Checking to see if the metadata for the current file we are on is a directory and is not a "." directory.
                if (file->getMeta()->getType() == TSK_FS_META_TYPE_DIR && !TSK_FS_ISDOT(file->getName()->getName()))
                {
                    //Checks to see if the file address we are currently looking at has been looked at already.
                    if (tsk_stack_find(addressStack, file->getMeta()->getAddr()) == 0)
                    {
                        //Adds the address to the stack so we know that the file has been looked at already
                        tsk_stack_push(addressStack, file->getMeta()->getAddr());
                        //Gets the file name
                        std::string fileName = file->getName()->getName();
                        //Checks to see if the file is a directory of interest.
                        if (fileName == "Windows" || fileName == "System32" || fileName == "config")
                        {
                            //Gets the size of the file
                            file->getMeta()->getSize();
                            //Checks to see if we have found the config directory where the SOFTWARE file is located.
                            if (fileName == "config")
                            {
                                //Extracts the SOFTWARE file from the directory
                                extractDirectoryFiles(selectedFS, file->getMeta()->getAddr());
                            }
                            findWindowsBinary(selectedFS, file->getMeta()->getAddr(), addressStack);
                        }
                        //Checks to see if it found the Users directory and looks at each user's folder to locate their NTUSER.DAT file
                        else if (fileName == "Users")
                        {
                            //Processes each user's desired information
                            findUserDATFiles(selectedFS, file->getMeta()->getAddr(), addressStack);
                        }
                    }
                }
            }
            //Closes the file and frees up memory space
            file->close();
            delete file;
        }
    }
    //Closes the directory and frees up memory space
    directory->close();
    delete directory;
}
//This method analyzes the volume system of the image file that was provided
void processVolumeWindows(TskImgInfo* imageFile, TSK_OFF_T volumeOffset)
{
    TskVsInfo* volumeSystem = new TskVsInfo();//Object Represents out Volume System
    //Error checking for volume system
    //Checks to make sure the volume can be opened
    if (volumeSystem->open(imageFile, volumeOffset, TSK_VS_TYPE_DETECT) != 0)
    {
        if (tsk_verbose)
        {
            std::cout << "Error determining volume system" << std::endl;
        }
        TskFsInfo* fileSystem = new TskFsInfo();
        if (fileSystem->open(imageFile, volumeOffset, TSK_FS_TYPE_DETECT) == 0)
        {
            //std::cout << "I'm a file system!" << std::endl;
        }
        delete fileSystem;
    }
    else
    {
        //Prints out information about the volume
        //Iterates through all partitions and checks to see if the partitions are unallocated or allocated
        for (TSK_PNUM_T i = 0; i < volumeSystem->getPartCount(); i++)
        {
            //Checks to see if it retrieved a valid partition.
            if (volumeSystem->getPart(i) == NULL)
            {
               //No partition was found and it moves on.
            }
            else
            {
                //std::cout << "Partition #" << i + 1 << ": " << std::endl;
                //Processes the selected partition.
                const TskVsPartInfo* partition = volumeSystem->getPart(i);
                TskFsInfo* fileSystem = new TskFsInfo();
                if ((fileSystem->open(imageFile, partition->getStart() * volumeSystem->getBlockSize(), TSK_FS_TYPE_DETECT)) != 0)
                {
                    //Do nothing since the volume is unallocated.
                }
                else
                {
                    TSK_STACK* addressStack = tsk_stack_create();
                    //Analyzes that volume system
                    findWindowsBinary(fileSystem, fileSystem->getRootINum(), addressStack);
                    tsk_stack_free(addressStack);
                }
                //Delete the file system
                delete fileSystem;
            }
        }
        //Closes the volume when we are done.
        volumeSystem->close();
    }
    //Deletes the volume system
    delete volumeSystem;
}

void VHDX_ExtractorWindows(TSK_TCHAR** p)
{
    //Creates Image object
    TskImgInfo* imageFile = new TskImgInfo();
    //Automatically detects image type and opens the image provided in LibTSK
    imageFile->open((const TSK_TCHAR*)p[1], TSK_IMG_TYPE_DETECT, 0);
    //Prints an error if no image is provided.
    if (imageFile == NULL) {
        //fprintf(stderr, "Error opening file\n");
        tsk_error_print(stderr);
        exit(1);
    }
    else
    {
        //Checks to see if the image provided is valid and processes the volume systems for that image
        if (imageFile->getSize() != 0)
        {
            processVolumeWindows(imageFile, 0);
        }
        else
        {
            std::cout << "No image detected!" << std::endl;
        }
    }
    //Deletes that image.
    delete imageFile;
}

//Struct that holds software name, version, and vendor
struct Data {

    std::string name;
    std::string version;
    std::string vendor;

};

//Function that compares if data struct is the same or not 
bool operator<(const Data& a, const Data& b) {
    //Case 1. Diff name
    //Case 2. Same name, diff version 
    return (a.name < b.name) || (a.name == b.name && a.version < b.version);
}

//Function that prints OS info and installed software, their version, and vendor to a .JSON file  
void writeFile(std::vector<std::string> d, const std::set<Data>& x, std::string fname) {

    std::ofstream file(fname);

    json a;

    if (d.at(1).empty()) {

        a = { {"Edition", d.at(0).c_str()},
       { "Current Build", d.at(2).c_str() } };
    }
    else {
        a = { {"Edition", d.at(0).c_str()},
        { "Version", d.at(1).c_str() },
        { "Current Build", d.at(2).c_str() } };
    }



    json tmp = {};

    for (const auto& s : x) {

        json d = { {"Name", s.name.c_str()}, {"Version" , s.version.c_str()},  {"Vendor", s.vendor.c_str()} };

        tmp.push_back(d);

    }

    json r = { a, tmp };

    file << r.dump(4);

    file.close();

}

//Function that prints information about the OS and installed software for debug 
void printData(const std::vector<std::string> a, const std::set<Data>& x) {

    for (const auto& s : a) {
        std::cout << s << std::endl;
    }

    for (const auto& s : x) {
        std::cout << "Software: " << s.name << std::endl <<
            "Version: " << s.version << std::endl <<
            "Vendor: " << s.vendor << std::endl << std::endl;
    }
}

//Function that returns the string value at a given key
std::string getValueStr(std::string val_name, libregf_value_t* sk, libregf_value_t* skv) {

    std::string str = "";
    //convert string to uint8
    const uint8_t* name_ = (const uint8_t*)val_name.c_str();

    libregf_key_get_value_by_utf8_name(sk, name_, val_name.size(), &skv, NULL);

    size_t str_size = 0;
    if (libregf_value_get_value_utf8_string_size(skv, &str_size, NULL) == 1) {

        uint8_t* utf8_string = new uint8_t[str_size];
        libregf_value_get_value_utf8_string(skv, utf8_string, str_size, NULL);
        std::string data(reinterpret_cast<char*>(utf8_string), str_size);
        str = data;

        delete[] utf8_string;
    }

    return str;

}
//Function that returns the 32 bit data value at a given key
uint32_t get32BitValue(std::string val_name, libregf_value_t* sk, libregf_value_t* skv) {

    std::string str = "";

    //convert string to uint8
    const uint8_t* name_ = (const uint8_t*)val_name.c_str();

    libregf_key_get_value_by_utf8_name(sk, name_, val_name.size(), &skv, NULL);

    uint32_t x;

    libregf_value_get_value_32bit(skv, &x, NULL);

    return x;
}

//Function that goes through all the subkeys from a given path to get name, version, nd vendor 
void getData(std::string key_path, libregf_file_t* file, std::set<Data>& f) {

    const uint8_t* kp = (const uint8_t*)key_path.c_str();

    libregf_key_t* key_ = NULL;

    if (libregf_file_get_key_by_utf8_path(file, kp, key_path.size(), &key_, NULL) == 1) {

        int len_sub_keys = 0;
        libregf_key_get_number_of_sub_keys(key_, &len_sub_keys, NULL);

        Data d;

        //Iterate all subkeys in the path and stores the name, version, and vendor
        for (int i = 0; i < len_sub_keys; i++) {
            libregf_key_t* sub_key = NULL;

            libregf_key_get_sub_key(key_, i, &sub_key, NULL);

            libregf_value_t* sub_key_val = NULL;

            std::string name = "DisplayName";
            d.name = getValueStr(name, sub_key, sub_key_val);

            std::string version = "DisplayVersion";
            d.version = getValueStr(version, sub_key, sub_key_val);

            std::string vendor = "Publisher";
            d.vendor = getValueStr(vendor, sub_key, sub_key_val);

            if (d.name.size() != 0) {
                f.insert(d);
            }

            //Free keys when done 
            libregf_key_free(&sub_key, NULL);
            libregf_key_free(&sub_key_val, NULL);

        }

    }

    libregf_key_free(&key_, NULL);

}
//Function that replaces the number from a given string with a number of choice 
std::string replaceNumber(const std::string& str, int newNumber) {
    std::regex regex("(\\d+)");
    return std::regex_replace(str, regex, std::to_string(newNumber));
}

//Function that information about the backup's OS 
void getOSInfo(libregf_file_t* file, std::vector<std::string>& data) {

    std::string name = "";
    std::string version = "";
    std::string currentbuild = "";

    int win11 = 22000;

    //relevant paths to get OS info from SOFTWARE file 
    std::string key_version_name = "Microsoft\\Windows NT\\CurrentVersion";

    //Free and intialize keys 
    const uint8_t* kp = (const uint8_t*)key_version_name.c_str();
    libregf_key_t* key_ = NULL;

    //Get value by the path of the key 
    if (libregf_file_get_key_by_utf8_path(file, kp, key_version_name.size(), &key_, NULL) == 1) {

        libregf_value_t* key_val = NULL;

        name = getValueStr("ProductName", key_, key_val);
        version = getValueStr("DisplayVersion", key_, key_val);
        currentbuild = getValueStr("CurrentBuild", key_, key_val);

        libregf_key_free(&key_, NULL);
        libregf_key_free(&key_val, NULL);
    }

    //Check if windows 11 and change the name 
    if (std::stoi(currentbuild) >= win11) {

        name = replaceNumber(name, 11);

    }

    if (name.size() != 0) {

        data.push_back(name);
        data.push_back(version);
        data.push_back(currentbuild);
    }

}

//Function that process software file
void handleSOFTWARE(std::vector<std::string>& v, std::set<Data>& f, std::string key_64_, std::string key_32_) {

    auto filename = "extracted_SOFTWARE";

    //allocate and intialize file structure 
    libregf_error_t* error = NULL;
    libregf_file_t* file = NULL;

    libregf_file_initialize(&file, NULL);

    //File open 
    if (libregf_file_open(file, filename, LIBREGF_OPEN_READ, &error) == 1)
    {

        //check 64bit 
        getData(key_64_, file, f);

        //check 32bit 
        getData(key_32_, file, f);

        //Get OS info
        getOSInfo(file, v);

    }
    else {
        //std::cout << "unable to open file." << std::endl;

        libregf_file_free(&file, NULL);
        libregf_error_free(&error);

        exit(EXIT_FAILURE);
    }

    //free file structure (it will also close a file if it was open)
    libregf_file_free(&file, &error);
}

//Function that process all NTUSER.DAT files
void handleNTUSER(std::set<Data>& f, std::string x) {

    //Go through all NTUSER.DAT files 
    for (int i = 0; i < userFiles.size(); i++) {

        //allocate and intialize file structure
        libregf_error_t* error = NULL;
        libregf_file_t* file = NULL;

        libregf_file_initialize(&file, NULL);

        //Open then get data 
        if (libregf_file_open(file, userFiles.at(i).c_str(), LIBREGF_OPEN_READ, &error) == 1) {

            getData(x, file, f);

        }
        else {
            //Unopen
            libregf_file_free(&file, NULL);
            libregf_error_free(&error);

            exit(EXIT_FAILURE);

        }

        //free file structure (it will also close a file if it was open)
        libregf_file_free(&file, &error);

    }

}

void getWindowsSoftware() {

    //store data 
    std::set<Data> softwareInfo;
    std::vector<std::string> osInfo;

    //relevant paths
    std::string key_64 = "\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    std::string key_32 = "\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    std::string NTUSER = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

    handleNTUSER(softwareInfo, NTUSER);

    handleSOFTWARE(osInfo, softwareInfo, key_64, key_32);

    //printData(osInfo, softwareInfo);

    writeFile(osInfo, softwareInfo, "Extracted_Software.json");

}

void removeFiles() {

    //Remove user file 
    for (auto& it : userFiles) {
        if (remove(it.c_str()) != 0)
        {
            perror("Error deleting file");
        }      
    }

}
/*LINUX IMPLEMENTATION*/
//Used for JSON formulation
std::vector<std::string> distroReturn() {
    std::ifstream currentFile; currentFile.open("Extracted_Software.json");
    std::string curLine, distro, versionNumber;
    std::getline(currentFile, curLine);
    distro = curLine;
    std::getline(currentFile, curLine);
    versionNumber = curLine;
    std::vector<std::string> output;
    output.push_back(distro);
    output.push_back(versionNumber);
    return output;
}
void processSoftwareLinux(TskFsFile* file)
{
    TSK_OFF_T fSize = file->getMeta()->getSize(); //Variable that represents the size of the SOFTWARE file
    char* softwareBuffer = (char*)malloc(2048); // Allocated 2048 bytes in the buffer that will be used to read the contents of the SOFTWARE.
    TSK_OFF_T off = 0;
    size_t len = 0;
    ssize_t cnt;
    int flag = 0;

    FILE* pFile; // File object that represents the file we will be creating
    //Creates a file object called extracted_SOFTWARE and gives it write binary permisions
    pFile = fopen("extracted_SOFTWARE.txt", "wb");
    fpos_t position;
    //This for loop allows our program to read the contents of the SOFTWARE file at 2048 bytes at a time into the buffer and then writes it into our newly created file.
    for (off = 0; off < fSize; off += len) {
        //Determines the length that needs to be read
        if (fSize - off < 2048)
            len = (size_t)(fSize - off);
        else
            len = 2048;
        //Transfers the contents of the actual file into the buffer
        cnt = file->read(off, softwareBuffer, len, (TSK_FS_FILE_READ_FLAG_ENUM)flag);
        //Checks to see if the file was unable to be read and returns an error message
        if (cnt == -1) {
            fprintf(stderr, "Error reading %s file: %s\n",
                ((file->getName()->getFlags()
                    & TSK_FS_NAME_FLAG_UNALLOC)
                    || (file->getMeta()->getFlags()
                        & TSK_FS_META_FLAG_UNALLOC)) ?
                "unallocated" : "allocated",
                file->getName()->getName());
            tsk_error_print(stderr);
            break;
        }
        //Writes the contents of the buffer into the newly created file
        fwrite(softwareBuffer, sizeof(char), len, pFile);
    }
    //Closes the file we are writing into and the file we were analyzing
    fclose(pFile);
    file->close();
}
void printFile(TskFsFile* file, const char* extractedName)
{
    TSK_OFF_T fSize = file->getMeta()->getSize(); //Variable that represents the size of the SOFTWARE file
    char* softwareBuffer = (char*)malloc(2048); // Allocated 2048 bytes in the buffer that will be used to read the contents of the SOFTWARE.
    TSK_OFF_T off = 0;
    size_t len = 0;
    ssize_t cnt;
    int flag = 0;

    FILE* pFile; // File object that represents the file we will be creating
    //Creates a file object called extracted_SOFTWARE and gives it write binary permisions
    pFile = fopen(extractedName, "wb");
    fpos_t position;
    //This for loop allows our program to read the contents of the SOFTWARE file at 2048 bytes at a time into the buffer and then writes it into our newly created file.
    for (off = 0; off < fSize; off += len) {
        //Determines the length that needs to be read
        if (fSize - off < 2048)
            len = (size_t)(fSize - off);
        else
            len = 2048;
        //Transfers the contents of the actual file into the buffer
        cnt = file->read(off, softwareBuffer, len, (TSK_FS_FILE_READ_FLAG_ENUM)flag);
        //Checks to see if the file was unable to be read and returns an error message
        if (cnt == -1) {
            fprintf(stderr, "Error reading %s file: %s\n",
                ((file->getName()->getFlags()
                    & TSK_FS_NAME_FLAG_UNALLOC)
                    || (file->getMeta()->getFlags()
                        & TSK_FS_META_FLAG_UNALLOC)) ?
                "unallocated" : "allocated",
                file->getName()->getName());
            tsk_error_print(stderr);
            break;
        }
        //Writes the contents of the buffer into the newly created file
        fwrite(softwareBuffer, sizeof(char), len, pFile);
    }
    //Closes the file we are writing into and the file we were analyzing
    fclose(pFile);
    file->close();
}
void txtToJson()
{
    //FILE* pFile; // File object that represents the file we will be creating
    //Creates a file object called extracted_SOFTWARE and gives it write binary permisions
    json c = {};

    std::ifstream currentFile; currentFile.open("extracted_SOFTWARE.txt");
    std::string curLine;
    bool packageFound = false;
    std::string package, maintainer, version, originalMaintainer;
    json a;
    std::vector<std::string> distroInfo = distroReturn();
    a = { {"Distribution", distroInfo.front()},{"Edition", distroInfo.back()} };

    std::ofstream returnFile("Extracted_Software.json", std::ios_base::trunc);
    if (currentFile.is_open()) {
        while (currentFile) {
            std::getline(currentFile, curLine);

            if (curLine.find("Package: ") != std::string::npos && curLine.find(":Package: ") == std::string::npos && curLine.find("-Package: ") == std::string::npos) {
                packageFound = true;
                package = curLine.substr(9, curLine.size() - 9);
            }
            else if (curLine.find("Maintainer: ") != std::string::npos && curLine[0] == 'M' && packageFound == true)
            {
                maintainer = curLine.substr(12, curLine.size() - 12);
            }
            else if (curLine.find("Version: ") != std::string::npos && curLine.find(":Version: ") == std::string::npos && curLine.find("-Version: ") == std::string::npos && packageFound == true) {
                version = curLine.substr(9, curLine.size() - 9);

            }
            else if (curLine.find("Original-Maintainer: ") != std::string::npos && packageFound == true) {
                originalMaintainer = curLine.substr(21, curLine.size() - 21);

            }
            else if (curLine == "") {
                packageFound = false;
                if (originalMaintainer == "") {
                    originalMaintainer = maintainer;
                }
                json d = { {"Name", package}, {"Version" , version},  {"Vendor", originalMaintainer} };
                c.push_back(d);
                originalMaintainer = "";
            }
        }
    }
    json r = { a , c };
    returnFile << r.dump(2);

    returnFile.close();

}
int getDatasqliteFedora(const char* filename, const char* sqlcmd) {
    json c = {};
    json a;
    std::vector<std::string> distroInfo = distroReturn();
    a = { {"Distribution", distroInfo.front()},{"Edition", distroInfo.back()} };
    std::ofstream returnFile("Extracted_Software.json", std::ios_base::trunc);
    sqlite3* db;
    int rc = sqlite3_open(filename, &db);
    if (rc != SQLITE_OK) {
        std::cerr << "Error opening database: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return 1;
    }

    sqlite3_stmt* stmt;
    const char* sql = sqlcmd;

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        std::cerr << "Error preparing SQL statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return 1;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        // Get the column value for the current row
        const unsigned char* name = sqlite3_column_text(stmt, 0);
        const unsigned char* ver = sqlite3_column_text(stmt, 1);
        //TODO: do smthn w the data 
        //std::cout << name << " " << ver << std::endl;
        std::string name2 = std::string(reinterpret_cast<const char*>(name));
        std::string ver2 = std::string(reinterpret_cast<const char*>(ver));
        json f = { {"Name", name2}, {"Version" , ver2} };
        c.push_back(f);
    }
    json r = { a, c };
    returnFile << r.dump(2);
    returnFile.close();
    //Close the file 
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}
int getDatasqliteCentOSV8(const char* filename, json a) {

    //Intializes and checks if database can be opened 
    sqlite3* db;
    json c = {};
    std::ofstream returnFile("Extracted_Software.json", std::ios_base::trunc);
    int file = sqlite3_open(filename, &db);

    if (file != SQLITE_OK) {
        std::cerr << "Error opening database: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return 1;
    }

    //checks if statement can be compiled into a byte-code 
    sqlite3_stmt* stmt;
    const char* query = "SELECT name, version FROM rpm";
    int prep = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);

    if (prep != SQLITE_OK) {
        std::cerr << "Error preparing SQL statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return 1;
    }

    //Get name, version, and vendor 
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* name = sqlite3_column_text(stmt, 0);
        const unsigned char* ver = sqlite3_column_text(stmt, 1);
        int id = sqlite3_column_int(stmt, 2);
        
        std::string name2 = std::string(reinterpret_cast<const char*>(name));
        std::string ver2 = std::string(reinterpret_cast<const char*>(ver));
        json f = { {"Name", name2}, {"Version" , ver2} };
        c.push_back(f);
    }
    json r = { a, c };
    returnFile << r.dump(2);
    returnFile.close();
    //Close the database and 1st query 
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return 0;
}
int getDatasqliteCentOS(const char* filename) {

    //Intializes and checks if database can be opened 
    sqlite3* db;
    json c = {};
    json a;
    std::vector<std::string> distroInfo = distroReturn();
    a = { {"Distribution", distroInfo.front()},{"Edition", distroInfo.back()} };
    std::ofstream returnFile("Extracted_Software.json", std::ios_base::trunc);
    int file = sqlite3_open(filename, &db);

    if (file != SQLITE_OK) {
        std::cerr << "Error opening database: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return 1;
    }

    //checks if statement can be compiled into a byte-code 
    sqlite3_stmt* stmt;
    const char* query = "SELECT name, version, pkgtupid FROM pkgtups";
    int prep = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    if (prep != SQLITE_OK) {
        getDatasqliteCentOSV8(filename, a);
        sqlite3_close(db);
        return 0;
    }

    //Get name, version, and vendor 
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* name = sqlite3_column_text(stmt, 0);
        const unsigned char* ver = sqlite3_column_text(stmt, 1);
        int id = sqlite3_column_int(stmt, 2);

        // Query another table using the id from the previous query 
        std::string query2 = "SELECT rpmdb_val FROM pkg_rpmdb WHERE pkgtupid = ? AND rpmdb_key = 'url'";
        sqlite3_stmt* stmt2;

        int prep2 = sqlite3_prepare_v2(db, query2.c_str(), -1, &stmt2, NULL);
        //checks if statement can be compiled into a byte-code 
        if (prep2 != SQLITE_OK) {
            std::cerr << "Error preparing SQLite statement: " << sqlite3_errmsg(db) << std::endl;
            sqlite3_close(db);
            return 1;
        }

        //binds the ID from the previous query to the current query to get the vendor information which is located in a different table 
        sqlite3_bind_int(stmt2, 1, id);
        prep2 = sqlite3_step(stmt2);

        const unsigned char* url = sqlite3_column_text(stmt2, 0);
        std::string ven_link = "";
        //URL exist convert to string 
        if (url != NULL) {

            ven_link = (reinterpret_cast<char const*>(url));

        }
        std::string name2 = std::string(reinterpret_cast<const char*>(name));
        std::string ver2 = std::string(reinterpret_cast<const char*>(ver));
        //std::string vendor2 = std::string(reinterpret_cast<const char*>(ven_link));
        json f = { {"Name", name2}, {"Version" , ver2}, {"Vendor" , ven_link} };
        c.push_back(f);
        //Close 2nd query 
        sqlite3_finalize(stmt2);
    }
    json r = { a, c };
    returnFile << r.dump(2);
    returnFile.close();
    //Close the database and 1st query 
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return 0;
}


void extractDirectoryFilesLinuxUbuntu(TskFsInfo* selectedFS, TSK_INUM_T volumeOffset)
{
    TskFsDir* directory = new TskFsDir();
    //Checks to see if the directory can be opened
    if (directory->open(selectedFS, volumeOffset) != 0)
    {
        std::cout << "  Error opening directory!" << std::endl;
    }
    else
    {
        //Iterates through the directories to extract necessary files SOFTWARE and NTUSER.DAT
        for (size_t i = 0; i < directory->getSize(); i++)
        {
            TskFsFile* file = directory->getFile(i);
            std::string fileName = file->getName()->getName();
            TSK_FS_NAME_TYPE_ENUM fileExtension = file->getName()->getType();
            //Recursively goes through filesystem until it reaches var/lib/dpkg
            if (fileName == "var" || fileName == "lib" || fileName == "dpkg") {
                extractDirectoryFilesLinuxUbuntu(selectedFS, file->getMeta()->getAddr());
            }
            //Finds file named status which contains the packages
            if (fileName == "status") {
                std::cout << "Processing status file" << std::endl;
                processSoftwareLinux(file);
                std::cout << "Creating JSON Software List" << std::endl;
                txtToJson();
            }
        }
    }
}
void extractDirectoryFilesLinuxFedora(TskFsInfo* selectedFS, TSK_INUM_T volumeOffset)
{
    TskFsDir* directory = new TskFsDir();
    //Checks to see if the directory can be opened
    if (directory->open(selectedFS, volumeOffset) != 0)
    {
        std::cout << "  Error opening directory!" << std::endl;
    }
    else
    {
        //Iterates through the directories to extract necessary files SOFTWARE and NTUSER.DAT
        for (size_t i = 0; i < directory->getSize(); i++)
        {
            TskFsFile* file = directory->getFile(i);
            std::string fileName = file->getName()->getName();
            TSK_FS_NAME_TYPE_ENUM fileExtension = file->getName()->getType();
            //Recursively finds the var/lib/dnf where history.sqlite file sits
            if (fileName == "var" || fileName == "lib" || fileName == "dnf") {
                
                extractDirectoryFilesLinuxFedora(selectedFS, file->getMeta()->getAddr());
            }
            if (fileName == "history.sqlite")
            {
                std::cout << "Reading history.sqlite file." << std::endl;
                const char* extractedNameChar = "history.sqlite";
                printFile(file, extractedNameChar);
                //Adds file to list of files to be deleted
                getDatasqliteFedora(extractedNameChar, "SELECT name, version FROM rpm");

            }
        }
    }
}
void extractDirectoryFilesLinuxCentOS(TskFsInfo* selectedFS, TSK_INUM_T volumeOffset)
{
    TskFsDir* directory = new TskFsDir();
    //Checks to see if the directory can be opened
    if (directory->open(selectedFS, volumeOffset) != 0)
    {
        std::cout << "  Error opening directory!" << std::endl;
    }
    else
    {
        //Iterates through the directories to extract necessary files SOFTWARE and NTUSER.DAT
        for (size_t i = 0; i < directory->getSize(); i++)
        {
            TskFsFile* file = directory->getFile(i);
            std::string fileName = file->getName()->getName();
            TSK_FS_NAME_TYPE_ENUM fileExtension = file->getName()->getType();
            //Recursively goes through the file system until it reaches needed path
            if (fileName == "var" || fileName == "lib" || fileName == "yum" || fileName == "history" || fileName == "dnf") {
                extractDirectoryFilesLinuxCentOS(selectedFS, file->getMeta()->getAddr());
            }
            //File is named history-date.sqlite so it parses for it
            if (fileName.find("history") != -1 && fileName.find(".sqlite") != -1 && fileName.find(".sqlite-") == -1)
            {
                std::cout << "Reading history.sqlite file." << std::endl;
                const char* extractedNameChar = "history.sqlite";
                printFile(file, extractedNameChar);
                getDatasqliteCentOS(extractedNameChar);
                std::cout << "Creating JSON Software List" << std::endl;
            }
        }
        //std::cout << "done with directory files\n";
    }
}

//For Linux Files
void findLinuxBinary(TskFsInfo* selectedFS, TSK_INUM_T volumeOffset, int& directoryCounter, TSK_STACK* addressStack, std::string fileType)
{
    //std::cout << "Finding Linux Binary" << std::endl;
    TskFsDir* directory = new TskFsDir();
    //Makes sure the FS provides is a directory type
    if (directory->open(selectedFS, volumeOffset) != 0)
    {
        std::cout << "  Error opening directory!" << std::endl;
    }
    else
    {
        //Iterates through the directory
        for (size_t i = 0; i < directory->getSize(); i++)
        {
            //Gets items located in the directory
            TskFsFile* file = directory->getFile(i);
            if (file == NULL)
            {
                std::cout << "  Could not get file" << std::endl;
            }
            else
            {
                //Checks to see if the file we are currently looking at is a file type.
                //Checking to see if the metadata for that folder is a directory.
                if (file->getMeta()->getType() == TSK_FS_META_TYPE_DIR && !TSK_FS_ISDOT(file->getName()->getName()))
                {
                    //Checks to see if the file address we are looking has been looked at already
                    if (tsk_stack_find(addressStack, file->getMeta()->getAddr()) == 0)
                    {
                        //Adds the address to the stack so we know that the file has been looked at already
                        tsk_stack_push(addressStack, file->getMeta()->getAddr());
                        std::string fileName = file->getName()->getName();
                        if (fileName == "var") {
                            if (fileType.find("Ubuntu") != -1) {
                                std::cout << "Ubuntu Distribution Detected" << std::endl;
                                extractDirectoryFilesLinuxUbuntu(selectedFS, file->getMeta()->getAddr());
                                userFiles.push_back("DistroInfo.txt");
                                userFiles.push_back("extracted_SOFTWARE.txt");
                            }
                            else if (fileType.find("CentOS") != -1) {
                                std::cout << "CentOS Distribution Detected" << std::endl;
                                extractDirectoryFilesLinuxCentOS(selectedFS, file->getMeta()->getAddr());
                                userFiles.push_back("DistroInfo.txt");
                                userFiles.push_back("history.sqlite");
                            }
                            else if (fileType.find("Fedora") != -1) {
                                std::cout << "Fedora Distribution Detected" << std::endl;
                                extractDirectoryFilesLinuxFedora(selectedFS, file->getMeta()->getAddr());
                                userFiles.push_back("DistroInfo.txt");
                                userFiles.push_back("history.sqlite");
                            }
                        }
                    }
                }
            }
        }
    }

}

std::vector<std::string> parseForDistro(std::string fileName) {
    std::ifstream currentFile; currentFile.open(fileName);
    std::string curLine, distro, versionNumber;
    while (currentFile) {
        std::getline(currentFile, curLine);
        //Gets the distribution name
        if (curLine.substr(0, 5) == "NAME=") {
            distro = curLine.substr(6, curLine.size() - 7);
        }
        //Gets the distribution version
        if (curLine.substr(0, 8) == "VERSION=") {
            versionNumber = curLine.substr(9, curLine.size() - 10);
        }
    }
    //Adds the contents into a vector
    std::vector<std::string> output;
    output.push_back(distro);
    output.push_back(versionNumber);
    std::ofstream returnFile("Extracted_Software.json");
    returnFile << distro << "\n";
    returnFile << versionNumber;
    returnFile.close();

    return output;

}

std::string extractLinuxType(TskFsInfo* selectedFS, TSK_INUM_T volumeOffset, TSK_STACK* addressStack) {

    //std::cout << "Finding Linux Binary" << std::endl;
    TskFsDir* directory = new TskFsDir();
    //Makes sure the FS provides is a directory type
    if (directory->open(selectedFS, volumeOffset) != 0)
    {
        std::cout << "  Error opening directory!" << std::endl;
    }
    else
    {
        //Iterates through the directory
        for (size_t i = 0; i < directory->getSize(); i++)
        {
            //Gets items located in the directory
            TskFsFile* file = directory->getFile(i);
            if (file == NULL)
            {
                std::cout << "  Could not get file" << std::endl;
            }
            else
            {
                //Checks to see if the file we are currently looking at is a file type.
                //Checking to see if the metadata for that folder is a directory.
                std::string fileName = file->getName()->getName();
                if (file->getMeta()->getType() == TSK_FS_META_TYPE_DIR && !TSK_FS_ISDOT(file->getName()->getName()))
                {
                    //Checks to see if the file address we are looking has been looked at already
                    if (tsk_stack_find(addressStack, file->getMeta()->getAddr()) == 0)
                    {
                        //Adds the address to the stack so we know that the file has been looked at already
                        tsk_stack_push(addressStack, file->getMeta()->getAddr());
                        if (fileName == "lib") {
                            //std::cout << "libFound!";
                            return extractLinuxType(selectedFS, file->getMeta()->getAddr(), addressStack);
                            break;
                        }
                    }
                }
                else if (fileName == "os-release") {
                    printFile(file, "DistroInfo.txt");
                    return parseForDistro("DistroInfo.txt").front();

                }
            }
        }
    }
}
std::string findLinuxDistro(TskFsInfo* selectedFS, TSK_INUM_T volumeOffset, int& directoryCounter, TSK_STACK* addressStack)
{
    TskFsDir* directory = new TskFsDir();
    //Makes sure the FS provides is a directory type
    if (directory->open(selectedFS, volumeOffset) != 0)
    {
        std::cout << "  Error opening directory!" << std::endl;
    }
    else
    {
        //Iterates through the directory
        for (size_t i = 0; i < directory->getSize(); i++)
        {
            //Gets items located in the directory
            TskFsFile* file = directory->getFile(i);
            if (file == NULL)
            {
                std::cout << "  Could not get file" << std::endl;
            }
            else
            {
                //Checks to see if the file we are currently looking at is a file type.
                //Checking to see if the metadata for that folder is a directory.
                if (file->getMeta()->getType() == TSK_FS_META_TYPE_DIR && !TSK_FS_ISDOT(file->getName()->getName()))
                {
                    //Checks to see if the file address we are looking has been looked at already
                    if (tsk_stack_find(addressStack, file->getMeta()->getAddr()) == 0)
                    {
                        //Adds the address to the stack so we know that the file has been looked at already
                        tsk_stack_push(addressStack, file->getMeta()->getAddr());
                        std::string fileName = file->getName()->getName();
                        if (fileName == "usr" || fileName == "etc") {
                            //std::cout << "USR found!\n";
                            std::string outputOS = extractLinuxType(selectedFS, file->getMeta()->getAddr(), addressStack);
                            if (outputOS != "")
                            {
                                return outputOS;
                            }
                        }
                    }
                }
            }
        }
        return "notfound";


    }

}
void processVolumeLinux(TskImgInfo* imageFile, TSK_OFF_T volumeOffset)
{
    TskVsInfo* volumeSystem = new TskVsInfo();
    TSK_POOL_TYPE_ENUM pooltype = TSK_POOL_TYPE_DETECT;
    //Error checking for volume system
    if (volumeSystem->open(imageFile, volumeOffset, TSK_VS_TYPE_DETECT) != 0)
    {
        std::cout << "Not a volume!" << std::endl;
        if (tsk_verbose)
        {
            std::cout << "Error determining volume system" << std::endl;
        }
        TskFsInfo* fileSystem = new TskFsInfo();
        if (fileSystem->open(imageFile, volumeOffset, TSK_FS_TYPE_DETECT) == 0)
        {
            std::cout << "I'm a file system!" << std::endl;
        }
        delete fileSystem;
    }
    else
    {
        //Iterates through all partitions and checks to see if the partitions are unallocated or allocated
        for (TSK_PNUM_T i = 0; i < volumeSystem->getPartCount(); i++)
        {
            //Checks to see if it retrieved a valid partition.
            if (volumeSystem->getPart(i) == NULL)
            {
                std::cout << "There was an error retrieving the partition." << std::endl;
            }
            else
            {
                //Processes the selected partition.
                const TskVsPartInfo* partition = volumeSystem->getPart(i);
                TskFsInfo* fileSystem = new TskFsInfo();
                TSK_OFF_T desiredAddress = partition->getStart() * volumeSystem->getBlockSize();
                const TSK_POOL_INFO *pool = tsk_pool_open_img_sing(imageFile->getm_imgInfo(), partition->getStart() * imageFile->getm_imgInfo()->sector_size, pooltype);
                if ((fileSystem->open(imageFile, desiredAddress, TSK_FS_TYPE_DETECT)) != 0)
                {
                    if (pool == nullptr)
                    {
                        //std::cout << "Unallocated" << std::endl;
                    }
                    else
                    {
                        //Checks to see if lvm directory index
                        if (lvmDirectoryIndex == -1)
                        {
                            std::cout << "Please specify index of 'root' directory in LVM." << std::endl;
                        }
                        else
                        {
                            //Creates an image object for root directory
                            TSK_IMG_INFO* lvmImage = pool->get_img_info(pool, (TSK_DADDR_T)lvmDirectoryIndex);
                            if (lvmImage == NULL)
                            {
                                std::cout << "LVM was not detected!" << std::endl;
                            }
                            //Opens file system with root directory
                            TskImgInfo* imageFile = new TskImgInfo(lvmImage);
                            if ((fileSystem->open(imageFile, partition->getStart() * lvmImage->sector_size, TSK_FS_TYPE_DETECT)) != 0)
                            {
                                std::cout << "Can't Open given Index" << std::endl;
                            }
                            else
                            {
                                //Feeds root directory into Linux extraction methods
                                std::cout << "LVM Detected" << std::endl;
                                int x = 0;
                                TSK_STACK* addressStack1 = tsk_stack_create();
                                TSK_STACK* addressStack2 = tsk_stack_create();
                                std::string fileType = findLinuxDistro(fileSystem, fileSystem->getRootINum(), x, addressStack1);
                                tsk_stack_free(addressStack1);
                                if (fileType != "notfound") {
                                    findLinuxBinary(fileSystem, fileSystem->getRootINum(), x, addressStack2, fileType);
                                }
                                tsk_stack_free(addressStack2);
                                removeFiles();
                                std::cout << "Linux Software Asset Extraction Completed." << std::endl;
                            }
                        }
                        //Deletes filesystem
                        delete fileSystem;
                    }
                }
                else
                {
                    int x = 0;
                    TSK_STACK* addressStack1 = tsk_stack_create();
                    TSK_STACK* addressStack2 = tsk_stack_create();
                    std::string fileType = findLinuxDistro(fileSystem, fileSystem->getRootINum(), x, addressStack1);
                    tsk_stack_free(addressStack1);
                    if (fileType != "notfound") {
                        std::cout << "Determining Linux Binary" << std::endl;
                        findLinuxBinary(fileSystem, fileSystem->getRootINum(), x, addressStack2, fileType);
                    }

                    tsk_stack_free(addressStack2);
                }
                delete fileSystem;
            }

        }
        //Closes the volume when we are done.
        volumeSystem->close();
    }

    delete volumeSystem;
}

void VHDX_ExtractorLinux(TSK_TCHAR** p)
{
    TskImgInfo* imageFile = new TskImgInfo();
    imageFile->open((const TSK_TCHAR*)p[1], TSK_IMG_TYPE_DETECT, 0);
    if (imageFile == NULL) {
        fprintf(stderr, "Error opening file\n");
        tsk_error_print(stderr);
        exit(1);
    }
    else
    {
      
        if (imageFile->getSize() != 0)
        {
            processVolumeLinux(imageFile, 0);
        }
        else
        {
            std::cout << "No image detected!" << std::endl;
        }
    }
    delete imageFile;

}

/*END OF LINUX IMPLEMENTATION*/

int main(int argc, char* argv1[])
{
    TSK_TCHAR** filePath = CommandLineToArgvW(GetCommandLineW(), &argc);
    std::string osType;
    std::string argumentFlag;
    if (argc > 3)
    {
        std::string index = argv1[3];
        lvmDirectoryIndex = stoi(index);
    }
    if (argc > 2)
    {
      argumentFlag = argv1[2];
      if (argumentFlag == "-W")
      {
          osType = "W";
          std::cout << "Processing Windows Type" << std::endl;
      }
      else if (argumentFlag == "-L")
      {
          osType = "L";
          std::cout << "Processing Linux Type" << std::endl;
      }
      //Calls Windows Extractor
      if (osType == "W")
      {
          VHDX_ExtractorWindows(filePath);
          getWindowsSoftware();
          removeFiles();
          std::cout << "Windows Software Asset Extraction Completed." << std::endl;
      }
      //Calls Linuz Extractor
      else if (osType == "L")
      {
          VHDX_ExtractorLinux(filePath);
          //Deletes extra files
          removeFiles();
          std::cout << "Linux Software Asset Extraction Completed." << std::endl;
      }
      else
      {
          std::cout << "Invalid input given! Please use -W for a Windows Operating System and -L for a Linux Operating system." << std::endl;
      }
    }
    else
    {
        std::cout << "Invalid number of parameters given! Command should be formatted as follows 'VHD_Extractor.exe [image name] [-W (Windows OS) or -L (Linux OS)] [LVM directory number if applicable]' " << std::endl;
    }
   
    return 0;
    
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
