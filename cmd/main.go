package main

import "github.com/alecthomas/kong"

var cli MainCommand

func main() {
	ctx := kong.Parse(&cli)
	// Call the Run() method of the selected parsed command.
	err := ctx.Run(cli)
	ctx.FatalIfErrorf(err)
}
