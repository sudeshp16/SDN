#ifndef __MYSQL_CONNECTOR_H__
#define __MYSQL_CONNECTOR_H__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mysql.h>


typedef enum MYSQLConnectorQueryType
{
	QTYPE_INSERT,
	QTYPE_UPDATE,
	QTYPE_SELECT
}MYSQLConnectQueryType;

typedef struct MYSQLConnector
{
	struct MYSQLConnector * (*init)(struct MYSQLConnector *this, 
													char *address, 
														char *user, 
													char *passwd, 
													char *Database, 
													short port, 
													char *unix_socket, 
															int flags);
	void (*exit)(struct MYSQLConnector *this);
	int (*MakeQuery)(struct MYSQLConnector *this,
                					char *query, 
					MYSQLConnectQueryType qtype,
                                      char ***results);
 	MYSQL *mysql;
	MYSQL_RES *result;
	MYSQL_ROW row;
	int no_of_cols;
	int no_of_rows;
}MYSQLConnector;

MYSQLConnector * 
	MYSQLConnector_init(MYSQLConnector *this, 
								char *address, 
								char *user, 
								char *passwd, 
								char *Database, 
								short port, 
								char *unix_socket, 
											int flags);

void MYSQLConnector_exit(MYSQLConnector *this);

int 
MYSQLConnector_MakeQuery(MYSQLConnector * this, 
									char *query, 
						MYSQLConnectQueryType qtype, 
										char ***results);



#endif	// __MYSQL_CONNECTOR_H__
