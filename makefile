CC= gcc
F= -O2 -pg 
SRC= ./src/
INC= ./include/
TST= ./test/
OBJS= main.o cry.o sha1.o aese.o aesd.o tab.o getval.o base64.o buffer.o key.o


wencry: $(OBJS)
	$(CC) $(F) $^ -o wencry

cmp: $(TST)test.c
	$(CC) $(TST)test.c -o cmp

test_once:
	make wencry
	make cmp
	./wencry -e $(TST)testfile.txt ABEiM0RVZneImaq7zN3u/w==
	./wencry -d $(TST)testfile.txt.wenc ABEiM0RVZneImaq7zN3u/w== $(TST)testout.txt
	./cmp $(TST)testfile.txt $(TST)testout.txt
	./wencry -e $(TST)t2.txt ABEiM0RVZneImaq7zN3u/w==
	./wencry -d $(TST)t2.txt.wenc ABEiM0RVZneImaq7zN3u/w== $(TST)t2out.txt
	./cmp $(TST)t2.txt $(TST)t2out.txt
	rm -rf $(TST)*.wenc $(TST)testout.txt $(TST)t2out.txt

analysis:
	make wencry
	./wencry -e $(TST)a.mp4 ABEiM0RVZneImaq7zN3u/w==
	gprof wencry gmon.out > res.out

%.o: $(SRC)%.c
	$(CC) $(F) -c $< -o $@

clean:
	rm -rf *.o *.out wencry cmp

format:
	clang-format -i $(SRC)*.c
	clang-format -i $(TST)*.c
	clang-format -i $(INC)*.h
	clang-format -i $(INC)util/*.h
