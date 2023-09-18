
F= -O2
SRC= ./src/
INC= ./include/
TST= ./test/

test_once: 
	make wencry
	make cmp
	./wencry -e $(TST)testfile.txt ABEiM0RVZneImaq7zN3u/w==
	./wencry -d $(TST)testfile.txt.wenc ABEiM0RVZneImaq7zN3u/w== $(TST)testout.txt
	./cmp $(TST)testfile.txt $(TST)testout.txt
	rm -rf $(TST)testfile.txt.wenc $(TST)testout.txt

format:
	clang-format -i $(SRC)*.c
	clang-format -i $(TST)*.c
	clang-format -i $(INC)*.h
	clang-format -i $(INC)util/*.h
	

wencry: main.o cry.o  sha1.o aese.o aesd.o tab.o getv.o base64.o
	gcc $(F)  main.o cry.o sha1.o aese.o aesd.o tab.o  getv.o base64.o -o wencry
	rm -rf *.o

main.o: $(SRC)main.c $(INC)cry.h $(INC)util.h
	gcc $(F) -c $(SRC)main.c -o main.o 

getv.o: $(SRC)getval.c $(INC)getval.h $(INC)cry.h $(INC)util.h
	gcc $(F) -c $(SRC)getval.c -o getv.o

base64.o: $(SRC)base64.c $(INC)getval.h $(INC)util.h
	gcc $(F) -c $(SRC)base64.c -o base64.o

cry.o: $(SRC)cry.c $(INC)cry.h $(INC)sha1.h $(INC)aes.h $(INC)util.h
	gcc $(F) -c $(SRC)cry.c -o cry.o

sha1.o: $(SRC)sha1.c $(INC)sha1.h $(INC)util.h
	gcc $(F) -c $(SRC)sha1.c -o sha1.o

aese.o: $(SRC)aese.c $(INC)aes.h $(INC)util.h
	gcc $(F) -c $(SRC)aese.c -o aese.o

aesd.o: $(SRC)aesd.c $(INC)aes.h $(INC)util.h
	gcc $(F) -c $(SRC)aesd.c -o aesd.o

tab.o: $(SRC)tab.c $(INC)aes.h $(INC)util.h
	gcc $(F) -c $(SRC)tab.c -o tab.o

clean:
	rm -rf *.o wencry cmp

cmp: $(TST)test.c
	gcc $(TST)test.c -o cmp