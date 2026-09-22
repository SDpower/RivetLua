static int callback(int value) { return value + 1; }
int main(void) { return callback(callback(0)) == 2 ? 0 : 1; }
