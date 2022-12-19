go-pewriter: main.go
	go build .

infile="test/TOTALCMD64.EXE"
outfile="test/TOTALCMD64.INJECTED.EXE"
payload="test-payload.json"

$(outfile): go-pewriter

write: go-pewriter 
	./go-pewriter -file $(infile) -payload $(payload) -write -out $(outfile)

read: write
	./go-pewriter -file $(outfile) -read

clean:
	rm -f ./go-pewriter $(outfile) ./test-payload.json
