

- malloc系列：TODO

```
"exit", "open", "close", "write", "clock",
"remove", "usleep", "stat", "access",
"fopen", "fclose", "fread", "fputs",//"fseek", "ftell", "lseek", "fseeko", "ftello",
"flock", "opendir", "readdir", "getpid", "getppid", "kill",
"prctl", "pipe", "fork", "waitpid", "execlp", "raise",
"puts", "printf", "sprintf", "snprintf", "fprintf", "scanf", "__iso99_scanf", "sscanf", "__iso99_sscanf", "fscanf", "__isoc99_fscanf", "strchr", "vprintf", "vfprintf",
"__aeabi_memclr4",
"eventfd", "poll"
```

- open fopen 转换为Path的构建。ok
- read fread 转换为文件读取 ok
- write fwrite fputs 转换为文件写入ok
- access stat 转Files.exists检查吧。
- remove 
- getpid getppid kill
- puts printf scanf 等等先不管。
- sprintf, snprintf 考虑直接转换为Phi。可能涉及malloc。
