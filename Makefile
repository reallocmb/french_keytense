program = ankicards

extern_lib = -lssl -lcrypto

compiler = clang $(develop_flags)

version =

release_flags = -std=$(version) -O3

develop_flags = -Wall -Wextra $(version) -g 

source_dir = src
object_dir = obj
binary_dir = bin
test_dir = tests

source_sub = $(wildcard src/*/*.c)
object_sub = $(patsubst $(source_dir)/%.c,$(object_dir)/%.o,$(source_sub))

source = $(wildcard $(source_dir)/*.c) 
object = $(patsubst $(source_dir)/%.c,$(object_dir)/%.o,$(source))

object_all = $(object) $(object_sub)

binary = $(binary_dir)/$(program)

sub_dirs = $(filter-out $(wildcard src/*.c) $(wildcard src/*.h),$(wildcard src/*))
objdirs = $(patsubst src/%,obj/%,$(sub_dirs))

all: $(objdirs) $(object_all) $(binary)

$(binary): $(object_all)
	$(compiler) -o $(binary) $(object_all) $(extern_lib)

$(object_dir)/%.o: $(source_dir)/%.c
	$(compiler) -c -o $@ $<

$(objdirs):
	@mkdir -p $@

run: all
	./$(binary) $(a)

gdb:
	gdb ./$(binary)

clean:
	rm $(object_dir)/* -r
	rm $(binary)

init:
	mkdir -p $(source_dir) $(object_dir) $(binary_dir) $(test_dir)/bin

install_dir = /usr/bin

install: compiler := gcc $(release_flags)
install: clean all
	sudo cp $(binary) $(install_dir)

release: 
	compiler = gcc $(release_flags)

remove:
	sudo rm $(install_dir)/$(program)

test:

print:
	@echo source: $(source)
	@echo source_sub: $(source_sub)
	@echo object_sub: $(object_sub)
	@echo object: $(object)
	@echo sub_dirs: $(sub_dirs) 
