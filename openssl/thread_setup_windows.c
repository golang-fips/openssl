//go:build windows
// +build windows
 
int go_openssl_thread_setup(void)
{
    // OpenSSL 1.0.2 not supported on Windows.
    return 0;
}
