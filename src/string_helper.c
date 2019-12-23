int Split(const char * in_string, char ***res_string, char * delimiter)
{
	if (!in_string || !res_string || !delimiter)
		return 0;
	int count = 0;
	char * res = NULL, *inp = NULL;
	inp = malloc(strlen(in_string)+ 1);
	if (!inp)
		return 0;
	strncpy(inp, in_string, strlen(in_string)+1);
	char * temp = strtok(inp, delimiter);
	*res_string = (char **)malloc(sizeof(char **));
	if (!(*res_string))
	{
		free(inp);
		return 0;
	}
	res  = (char *)malloc(strlen(temp) + 1); 
	strncpy(res, temp, strlen(temp)+1);
	(*res_string)[0] = res;
	while ((temp = strtok(NULL, delimiter)) != NULL)
	{
		count++;
		*res_string = (char **)realloc(*res_string, count*sizeof(char **));
		res = malloc(strlen(temp)+ 1);
		strncpy(res, temp, strlen(temp)+1);
		(*res_string)[count] = res;
	}
	free (inp);
	return ++count;	
}

void freefields(char ***fields, int count)
{
	int i = 0;
	if (!fields)
		return;
	if (!(*fields))
		return;
	for (i=0; i <count; i++)
	{
		free((*fields)[i]);
		(*fields)[i] = NULL;
	}
	free(*fields);
	*fields = NULL;
}
