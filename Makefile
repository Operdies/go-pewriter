go-pewriter: main.go
	go build .

infile="test/TOTALCMD64.EXE"
outfile="test/TOTALCMD64.INJECTED.EXE"
payload="test-payload.json"

$(outfile): go-pewriter

write: go-pewriter 
	./go-pewriter -file $(infile) -write -key testkey -payload $(payload) -out $(outfile)
	./go-pewriter -file $(outfile) -write -key another-key -payload <(echo -ne '"Some random key idk"') -out $(outfile)
	./go-pewriter -file $(outfile) -write -key another-key -payload <(echo -ne 'Overwritten key') -out $(outfile)

read: write
	./go-pewriter -file $(outfile) -read -key testkey -dump

clean:
	rm -f ./go-pewriter $(outfile) ./test-payload.json
