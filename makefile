CC= g++
F= -O3
SRC= ./src/
INC= ./include/
TST= ./test/
OUT= ./bin/
OBJS= main.o encry.o decry.o sha1.o aese.o aesd.o getval.o base64.o buffer.o key.o execval.o



wencry: $(OBJS)
	$(CC) $(F) $(OUT)*.o -o wencry -I $(INC) -I $(INC)util/

speedfile: $(TST)test_file.c
	$(CC) $(TST)test_file.c -o speedfile

cmp: $(TST)test.c
	$(CC) $(TST)test.c -o cmp

test_once:
	make wencry
	make cmp
	./wencry -e $(TST)testfile.txt ABEiM0RVZneImaq7zN3u/w==
	./wencry -v $(TST)testfile.txt.wenc ABEiM0RVZneImaq7zN3u/w==
	./wencry -d $(TST)testfile.txt.wenc ABEiM0RVZneImaq7zN3u/w== $(TST)testout.txt
	./cmp $(TST)testfile.txt $(TST)testout.txt
	./wencry -e $(TST)t2.txt ABEiM0RVZneImaq7zN3u/w==
	./wencry -v $(TST)t2.txt.wenc ABEiM0RVZneImaq7zN3u/w==
	./wencry -d $(TST)t2.txt.wenc ABEiM0RVZneImaq7zN3u/w== $(TST)t2out.txt
	./cmp $(TST)t2.txt $(TST)t2out.txt
	rm -rf $(TST)*.wenc $(TST)testout.txt $(TST)t2out.txt

analysis_git:
	make speedfile
	make wencry
	./speedfile $(TST)speed.txt
	./wencry -e $(TST)speed.txt ABEiM0RVZneImaq7zN3u/w==
	rm -rf $(TST)*.wenc $(TST)speed.txt

analysis:
	make wencry
	./wencry -e $(TST)a.mp4 ABEiM0RVZneImaq7zN3u/w==
	gprof wencry gmon.out > $(OUT)res.txt

%.o: $(SRC)%.cpp
	$(CC) $(F) -c $< -o $(OUT)$@ -I $(INC) -I $(INC)util/

clean:
	rm -rf $(OUT)*.o $(TST)*.wenc $(TST)aa.mp4 wencry cmp speedfile

format:
	clang-format -i $(SRC)*.cpp
	clang-format -i $(TST)*.c
	clang-format -i $(INC)*.h
	clang-format -i $(INC)util/*.h
