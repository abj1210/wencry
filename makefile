
F= -O2
SRC= ./src/
INC= ./include/

wencry: main.o cry.o sha1.o aese.o aesd.o tab.o
	gcc $(F)  main.o cry.o sha1.o aese.o aesd.o tab.o -o wencry
	rm -rf *.o

main.o: $(SRC)main.c $(INC)cry.h
	gcc $(F) -c $(SRC)main.c -o main.o 

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
	rm -rf *.o wencry