/*
Copyright (c) 2020. Wesley Shields. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/errno.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <yara/libyara.h>
#include <yara/types.h>
#include <yara/exec.h>

void* map_bytecode(char* src, off_t* size) {
  int fd;
  int result;
  struct stat file_stat;
  void* map;

  fd = open(src, O_RDONLY);
  if (fd == -1) {
    printf("%s\n", strerror(errno));
    return NULL;
  }

  result = fstat(fd, &file_stat);
  if (result == -1) {
    printf("%s\n", strerror(errno));
    close(fd);
    return NULL;
  }

  if (file_stat.st_size < 5) {
    printf("Bytecode too small.\n");
    close(fd);
    return NULL;
  }

  map = mmap(NULL, file_stat.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  if (map == MAP_FAILED) {
    printf("%s\n", strerror(errno));
    close(fd);
    return NULL;
  }
  close(fd);

  *size = file_stat.st_size;
  return map;
}

uint8_t* do_fixups(uint8_t* map, off_t size) {
  uint8_t* map_end;
  uint8_t* code_start;
  uint32_t fixups;
  uint32_t* fixup_p;
  uint32_t lb;
  uint32_t rb;

  map_end = map + size;
  if (map_end < map) {
    printf("Map overflow.\n");
    return NULL;
  }

  fixups = *(uint32_t*) map;
  fixup_p = (uint32_t*) (map + sizeof(uint32_t));
  code_start = (uint8_t*) (fixup_p + fixups * 2);
  while (fixups > 0) {
    if (fixup_p < (uint32_t*) map || fixup_p > (uint32_t*) map_end ||
        fixup_p + 2 > (uint32_t*) code_start) {
      printf("Invalid fixup.\n");
      return NULL;
    }

    lb = *fixup_p;
    rb = *(fixup_p + 1);

    if (code_start + lb > map_end || code_start + lb < code_start ||
        code_start + rb > map_end || code_start + lb < code_start) {
      printf("Invalid fixup offset.\n");
      return NULL;
    }

    *(int32_t*) (code_start + lb + 2) = (int32_t) ((code_start + rb + 6) - (code_start + lb));
    *(int32_t*) (code_start + rb + 2) = (int32_t) ((code_start + lb) - (code_start + rb) - 1);


    fixup_p += 2;
    fixups--;
  }

  return code_start;
}

int main(int argc, char **argv) {
  uint8_t* map;
  uint8_t* code_start;
  char* src;
  off_t size;
  YR_SCAN_CONTEXT* context;
  YR_RULES* rules;
  uint32_t stack_size = DEFAULT_STACK_SIZE;

  if (argc != 2)
    src = "a.out";
  else
    src = argv[1];

  map = map_bytecode(src, &size);
  if (map == NULL)
    return 1;

  code_start = do_fixups(map, size);
  if (code_start == NULL) {
    munmap(map, size);
    return 1;
  }

  context = (YR_SCAN_CONTEXT*) malloc(sizeof(YR_SCAN_CONTEXT));
  if (context == NULL) {
    printf("Unable to allocate context.\n");
    munmap(map, size);
    return 1;
  }

  rules = (YR_RULES*) malloc(sizeof(YR_RULES));
  if (rules == NULL) {
    printf("Unable to allocate rules.\n");
    munmap(map, size);
    free(context);
    return 1;
  }

  memset(context, 0, sizeof(YR_SCAN_CONTEXT));
  memset(rules, 0, sizeof(YR_RULES));

  context->rules = rules;
  rules->code_start = code_start;

  yr_set_configuration(YR_CONFIG_STACK_SIZE, &stack_size);
  (void) yr_execute_code(context);

  free(rules);
  free(context);
  munmap(map, size);

  return 0;
}
