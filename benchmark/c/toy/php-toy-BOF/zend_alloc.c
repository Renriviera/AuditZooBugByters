ZEND_API char* zend_strndup(const char *s, size_t length)
{
	char *p;

	p = (char *) malloc(length + 1);
	if (UNEXPECTED(p == NULL)) {
		zend_out_of_memory();
	}
	if (EXPECTED(length)) {
		memcpy(p, s, length);
	}
	p[length] = 0;
	return p;
}