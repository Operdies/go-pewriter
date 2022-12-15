go-pewriter: main.go
	go build .

infile="$(HOME)/tmp/Runner.exe"
outfile="Runner.Injected.exe"
payload="$$(cat ./test-payload.json)"

$(outfile): go-pewriter

write: go-pewriter 
	./go-pewriter -file $(infile) -payload $(payload) -write -out $(outfile)

read: write
	./go-pewriter -file $(outfile) -read

clean:
	rm -f ./go-pewriter $(outfile) ./test-payload.jsoN
