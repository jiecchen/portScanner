//
//  CFileOperation.h
//  netcat
//
//  Created by Tony Liu on 9/5/14.
//  Copyright (c) 2014 Tony Liu. All rights reserved.
//

#ifndef CFileOperation_h
#define CFileOperation_h
#include <pthread.h>
#include <iostream>
class CFileOperation
{
public:
    /*
     * @brief Constructor, do nothing
     */
    CFileOperation();
    /*
     * @brief Constructor, check path and create it
     * @param [in] path
     * @param [in] file name
     */
    CFileOperation(std::string strPath, std::string strFileName);
    /*
     * @brief Constructor, check path and create it
     * @param [in] full path
     */
    CFileOperation(std::string strPath);
    /*
     * @brief Destructor, close file before leave
     */
    ~CFileOperation();
    /**
     * @brief Write buffer to local file
     * @param [in] buffer
     * @return true/false
     */
    bool WriteFile(void * Buffer, unsigned iBufferLength);
    /**
     * @brief Write buffer to local file
     * @param [in] buffer
     * @return how many buffer read
     */
    int ReadFile(void * Buffer, int iOffset, unsigned iBufferLength);
    /**
     * @brief Write buffer to local file
     * @param [in] buffer
     * @return how many buffer read
     */
    int ReadFile(std::string strFileName, void * Buffer, int iOffset, unsigned iBufferLength);
    /**
     * @brief Open file if not opened
     * @return true/false
     */
    //bool OpenFile();

private:
    /*
     * @brief Initialize the mutex
     * @return true/false
     */
    bool InitMutex();
    /*
     * @brief Check the path exsit or not, if not, create it recursively
     * @param [in] path
     * @return true/false
     */
    bool CheckPath(std::string &strPath);
    /*
     * @brief Create path
     * @param [in] path
     * @return true/false
     */
    bool CreatePath(const std::string strPath)const;
private:
    //mutex to protect the file
    pthread_mutex_t m_Mutex;
    //local path to store file, default .
    std::string m_strLocalPath;
    //file name
    std::string m_strFileName;
    //file describer
    int m_iFileDescriber;
};

#endif
