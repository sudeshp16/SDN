#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mysql.h>
#include <MYSQLConnector.h>

MYSQLConnector * 
	MYSQLConnector_init(MYSQLConnector *this, 
								char *address, 
								char *user, 
								char *passwd, 
								char *Database, 
								short port, 
								char *unix_socket, 
											int flags)
{
  	this->mysql = mysql_init(NULL);
	if (!(this->mysql))
			return NULL;
	if (!mysql_real_connect(this->mysql,address, user, passwd, Database, port, unix_socket, flags))
	{
		printf("Failed to connect to Database : MYSQL Errno %d MYSQL State %s MYSQL Error %s\n", mysql_errno(this->mysql), mysql_sqlstate(this->mysql), mysql_error(this->mysql));
		return NULL;
	}
	printf("Connected to DB\n");
	return this;
}
EXPORT(MYSQLConnector_init);

void 
MYSQLConnector_exit(MYSQLConnector *this)
{
	mysql_close(this->mysql);
}

int 
MYSQLConnector_MakeQuery(MYSQLConnector * this, 
									char *query, 
						MYSQLConnectQueryType qtype, 
										char ***results)
{
	if(mysql_real_query(this->mysql, query, strlen(query)))
	{

		printf("Failed to make query errno %d mysql state %s mysql error %s", mysql_errno(this->mysql), mysql_sqlstate(this->mysql), mysql_error(this->mysql));
		return -1;
	}
	else
	{
		if (qtype == QTYPE_SELECT)
		{	// Work on Results
			this->result= mysql_store_result(this->mysql);
			if (this->result)
			{
				this->no_of_rows = mysql_num_rows(this->result);
				int i = 0;
				*results = (char **)malloc(this->no_of_rows*sizeof(char *));
				for (; i < this->no_of_rows; i++)
				{
					this->row = mysql_fetch_row(this->result);
					this->no_of_cols = mysql_num_fields(this->result);
					int j = 0;
					for (;j < this->no_of_cols; j++)
					{
						printf("%s|", (this->row)[j]);
					}
					printf("\n");
				}
				mysql_free_result(this->result);
				this->result = NULL;
				return this->no_of_rows;
			}
		}
		else	// Just Return Status
		{
			return 1;
		}
	}	
}

