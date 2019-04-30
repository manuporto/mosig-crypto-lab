# Universite Grenoble Alpes
## Master of Science in Informatics at Grenoble
### Introduction to Cryptology (GBIN8U16)
#### TP — Birthday attack on CBC
---

#### Building instructions
1. For building the tests, `g++ -Wformat=0 src/*.c src/*.cpp test/*.c`.
2. For building the attack program, from inside the attack directory run `g++ -Wformat=0 ../src/*.c ../src/*.cpp attack_main.c`.

#### Running instructions
Whether the test or the attack program was built, the running command it's the same since it doesn't receive any argument. The following command needs to be run then, `./a.out`.
