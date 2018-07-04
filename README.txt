The externals libraries used are dnsjava

Instructions to Run the program

I have written partA and partB in the same java file. SO you need to run only one java file.
It will give you the mydig output and also tell you whether the website is DNSSEC enabled or not

1) javac -cp .;dnsjava-2.1.1.jar Dnsresolver.java

2) java -cp .;dnsjava-2.1.1.jar Dnsresolver
   <domain_name> <type>

eg: java -cp .;dnsjava-2.1.1.jar Dnsresolver
    www.cnn.com A 