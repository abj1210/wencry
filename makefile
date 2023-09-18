
F= -O2
SRC= ./src/
INC= ./include/
TST= ./test/

test_once: 
	make wencry
	make cmp
	./wencry -e $(TST)testfile.txt 00112233445566778899aabbccddeeff
	./wencry -d $(TST)testfile.txt.wenc 00112233445566778899aabbccddeeff $(TST)testout.txt
	./cmp $(TST)testfile.txt $(TST)testout.txt

wencry: main.o cry.o  sha1.o aese.o aesd.o tab.o getv.o
	gcc $(F)  main.o cry.o sha1.o aese.o aesd.o tab.o  getv.o -o wencry
	rm -rf *.o

main.o: $(SRC)main.c $(INC)cry.h
	gcc $(F) -c $(SRC)main.c -o main.o 

getv.o: $(SRC)getval.c $(INC)getval.h $(INC)cry.h
	gcc $(F) -c $(SRC)getval.c -o getv.o

cry.o: $(SRC)cry.c $(INC)cry.h $(INC)sha1.h $(INC)aes.h
	gcc $(F) -c $(SRC)cry.c -o cry.o

sha1.o: $(SRC)sha1.c $(INC)sha1.h
	gcc $(F) -c $(SRC)sha1.c -o sha1.o

aese.o: $(SRC)aese.c $(INC)aes.h
	gcc $(F) -c $(SRC)aese.c -o aese.o

aesd.o: $(SRC)aesd.c $(INC)aes.h
	gcc $(F) -c $(SRC)aesd.c -o aesd.o

tab.o: $(SRC)tab.c $(INC)aes.h
	gcc $(F) -c $(SRC)tab.c -o tab.o

clean:
	rm -rf *.o wencry cmp

cmp: $(TST)test.c
	gcc $(TST)test.c -o cmp